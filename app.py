from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import re
import threading
from datetime import datetime
import qrcode
import io
import base64
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

_secret = os.environ.get('SECRET_KEY')
if not _secret:
    import secrets as _secrets
    _secret = _secrets.token_hex(32)
    app.logger.warning(
        "SECRET_KEY not set — generated random key. Sessions will reset on restart. "
        "Set SECRET_KEY in your .env file for production."
    )
app.secret_key = _secret

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

DB_PATH = os.path.join(os.path.dirname(__file__), 'parking.db')

SMTP_HOST     = 'smtp.gmail.com'
SMTP_PORT     = 587
SMTP_USER     = 'loke09102006@gmail.com'
SMTP_PASSWORD = 'mawbbspfzpdhffpf'
SMTP_FROM     = 'loke09102006@gmail.com'

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

VEHICLE_RE = re.compile(r'^[A-Z]{2}\d{1,2}[A-Z]{1,2}\d{4}$')

def valid_vehicle_number(v):
    return bool(VEHICLE_RE.match(v.upper().strip()))

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','entry_staff','exit_staff')),
            full_name TEXT,
            must_change_password INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS parking_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slot_code TEXT UNIQUE NOT NULL,
            zone TEXT NOT NULL,
            slot_number INTEGER NOT NULL,
            vehicle_type TEXT NOT NULL CHECK(vehicle_type IN ('2-wheeler','4-wheeler')),
            is_occupied INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS parking_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_number TEXT NOT NULL,
            vehicle_type TEXT NOT NULL,
            owner_name TEXT,
            owner_phone TEXT,
            owner_email TEXT,
            slot_id INTEGER REFERENCES parking_slots(id),
            entry_time TEXT DEFAULT (datetime('now','localtime')),
            exit_time TEXT,
            duration_minutes INTEGER,
            amount_due REAL,
            payment_method TEXT,
            payment_status TEXT DEFAULT 'pending',
            entry_staff_id INTEGER REFERENCES users(id),
            exit_staff_id INTEGER REFERENCES users(id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_records_vehicle   ON parking_records(vehicle_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_records_exit_time ON parking_records(exit_time)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_slots_occupied    ON parking_slots(is_occupied, vehicle_type)")


    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (username, password_hash, role, full_name, must_change_password) VALUES (?,?,?,?,?)",
            ('admin', generate_password_hash('admin123'), 'admin', 'System Administrator', 1)
        )

    # Seed parking slots
    all_slots = [(f'A{i}','A',i,'2-wheeler') for i in range(1,41)] + \
                [(f'B{i}','B',i,'4-wheeler') for i in range(1,41)]
    cur.executemany(
        "INSERT OR IGNORE INTO parking_slots (slot_code, zone, slot_number, vehicle_type) VALUES (?,?,?,?)",
        all_slots
    )

    # Seed default rates into settings table
    cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_2w', '20')")
    cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_4w', '35')")

    conn.commit()
    cur.close(); conn.close()


def get_rates():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM settings WHERE key IN ('rate_2w','rate_4w')")
    rows = {r[0]: float(r[1]) for r in cur.fetchall()}
    cur.close(); conn.close()
    return {'2-wheeler': rows.get('rate_2w', 30.0), '4-wheeler': rows.get('rate_4w', 50.0)}

def set_rates(rate_2w, rate_4w):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('rate_2w', ?)", (str(rate_2w),))
    cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('rate_4w', ?)", (str(rate_4w),))
    conn.commit()
    cur.close(); conn.close()


# ── User model ────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, id, username, role, full_name, must_change_password=0):
        self.id = id
        self.username = username
        self.role = role
        self.full_name = full_name
        self.must_change_password = bool(must_change_password)

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, role, full_name, must_change_password FROM users WHERE id=?", (user_id,))
        u = cur.fetchone()
        cur.close(); conn.close()
        if u:
            return User(u['id'], u['username'], u['role'], u['full_name'], u['must_change_password'])
    except Exception:
        pass
    return None


# ── Role-based access control (FIXED: always redirects on denial) ────────────

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if current_user.role not in roles:
                flash('Access denied — insufficient permissions.', 'danger')
                return redirect(url_for('dashboard'))   # always redirect
            return f(*args, **kwargs)
        return decorated
    return decorator


# ── Billing helpers ───────────────────────────────────────────────────────────

def calc_amount(entry_time, exit_time, vehicle_type):
    if isinstance(entry_time, str):
        entry_time = datetime.strptime(entry_time, '%Y-%m-%d %H:%M:%S')
    if isinstance(exit_time, str):
        exit_time = datetime.strptime(exit_time, '%Y-%m-%d %H:%M:%S')
    delta = exit_time - entry_time
    minutes = max(1, int(delta.total_seconds() / 60))
    half_hours = max(1, -(-minutes // 30))
    rates = get_rates()
    rate = rates.get(vehicle_type, 20)
    return minutes, round(half_hours * rate, 2)

def parse_dt(val):
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            continue
    return val

def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for key in ('entry_time', 'exit_time', 'created_at'):
        if key in d and d[key]:
            d[key] = parse_dt(d[key])
    return d

def rows_to_dicts(rows):
    return [row_to_dict(r) for r in rows]


# ── UPI QR code ───────────────────────────────────────────────────────────────

def generate_upi_qr(amount, vehicle_number):
    upi_id     = os.environ.get('UPI_ID', '7013455633-2@ybl')
    payee_name = os.environ.get('PAYEE_NAME', 'ParkingLot')
    upi_str = (
        f"upi://pay?pa={upi_id}"
        f"&pn={payee_name.replace(' ', '%20')}"
        f"&am={amount:.2f}"
        f"&cu=INR"
        f"&tn=Parking%20{vehicle_number}"
        f"&mc=7011"
    )
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(upi_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()


# ── Email receipt — sent in background thread (non-blocking) ─────────────────

def _send_email_worker(record):
    if not SMTP_USER or not SMTP_PASSWORD or not record.get('owner_email'):
        return
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"ParkOS Receipt #{record['id']:05d} — {record['vehicle_number']}"
        msg['From']    = SMTP_FROM
        msg['To']      = record['owner_email']
        et   = parse_dt(record['entry_time'])
        xt   = parse_dt(record['exit_time'])
        mins = record.get('duration_minutes', 0) or 0
        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;border:1px solid #ddd;border-radius:8px;overflow:hidden">
          <div style="background:#f5c842;padding:20px 24px">
            <h1 style="margin:0;font-size:22px;letter-spacing:3px;color:#0a0a0f">PARKOS</h1>
            <p style="margin:4px 0 0;font-size:12px;color:#333">Parking Receipt #{record['id']:05d}</p>
          </div>
          <div style="padding:24px">
            <table style="width:100%;border-collapse:collapse;font-size:14px">
              <tr><td style="color:#888;padding:6px 0">Vehicle</td><td style="font-weight:bold">{record['vehicle_number']}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Slot</td><td>{record.get('slot_code','')}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Entry</td><td>{et.strftime('%d %b %Y, %H:%M') if et else ''}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Exit</td><td>{xt.strftime('%d %b %Y, %H:%M') if xt else ''}</td></tr>
              <tr><td style="color:#888;padding:6px 0">Duration</td><td>{mins//60}h {mins%60}m</td></tr>
              <tr><td style="color:#888;padding:6px 0">Payment</td><td>{(record.get('payment_method') or '').upper()}</td></tr>
            </table>
            <div style="background:#fff8e0;border:2px solid #f5c842;border-radius:6px;padding:16px;text-align:center;margin-top:16px">
              <div style="font-size:12px;color:#888;text-transform:uppercase">Total Paid</div>
              <div style="font-size:28px;font-weight:bold;color:#e8a020">Rs. {record['amount_due']}</div>
            </div>
            <p style="color:#aaa;font-size:12px;text-align:center;margin-top:16px">Thank you for using ParkOS · Drive Safe</p>
          </div>
        </div>"""
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, record['owner_email'], msg.as_string())
        app.logger.info(f"Email receipt sent to {record['owner_email']} for record #{record['id']}")
    except Exception as e:
        app.logger.warning(f"Email send failed: {e}")

def send_email_receipt(record):
    """Fire-and-forget — does not block the HTTP response."""
    threading.Thread(target=_send_email_worker, args=(dict(record),), daemon=True).start()
    return True


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        u = cur.fetchone()
        cur.close(); conn.close()
        if u and check_password_hash(u['password_hash'], password):
            user_obj = User(u['id'], u['username'], u['role'], u['full_name'], u['must_change_password'])
            login_user(user_obj)
            if user_obj.must_change_password:
                flash('Please change your default password before continuing.', 'warning')
                return redirect(url_for('change_password'))
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Signed out successfully.', 'info')
    return redirect(url_for('login'))


# ── Forced password change on first login ─────────────────────────────────────

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw     = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id=?", (current_user.id,))
        row = cur.fetchone()
        if not row or not check_password_hash(row['password_hash'], current_pw):
            flash('Current password is incorrect.', 'danger')
        elif len(new_pw) < 8:
            flash('New password must be at least 8 characters.', 'danger')
        elif new_pw != confirm_pw:
            flash('New passwords do not match.', 'danger')
        else:
            cur.execute(
                "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                (generate_password_hash(new_pw), current_user.id)
            )
            conn.commit()
            flash('Password changed successfully!', 'success')
            cur.close(); conn.close()
            return redirect(url_for('dashboard'))
        cur.close(); conn.close()
    return render_template('change_password.html')


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.must_change_password:
        flash('Please change your default password before continuing.', 'warning')
        return redirect(url_for('change_password'))

    conn = get_db()
    cur = conn.cursor()

    def q1(sql):
        cur.execute(sql)
        r = cur.fetchone()
        return list(r)[0] if r else 0

    total_slots    = q1("SELECT COUNT(*) FROM parking_slots")
    occupied       = q1("SELECT COUNT(*) FROM parking_slots WHERE is_occupied=1")
    occ_2w         = q1("SELECT COUNT(*) FROM parking_slots WHERE is_occupied=1 AND vehicle_type='2-wheeler'")
    occ_4w         = q1("SELECT COUNT(*) FROM parking_slots WHERE is_occupied=1 AND vehicle_type='4-wheeler'")
    total_2w       = q1("SELECT COUNT(*) FROM parking_slots WHERE vehicle_type='2-wheeler'")
    total_4w       = q1("SELECT COUNT(*) FROM parking_slots WHERE vehicle_type='4-wheeler'")
    today_rev      = q1("SELECT COALESCE(SUM(amount_due),0) FROM parking_records WHERE payment_status='paid' AND DATE(exit_time)=DATE('now','localtime')")
    month_rev      = q1("SELECT COALESCE(SUM(amount_due),0) FROM parking_records WHERE payment_status='paid' AND strftime('%Y-%m',exit_time)=strftime('%Y-%m','now','localtime')")
    total_vehicles = q1("SELECT COUNT(*) FROM parking_records")

    cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                   JOIN parking_slots ps ON pr.slot_id=ps.id
                   WHERE pr.exit_time IS NULL ORDER BY pr.entry_time DESC LIMIT 10""")
    active_records = rows_to_dicts(cur.fetchall())

    cur.execute("""SELECT CAST(strftime('%H', entry_time) AS INTEGER) as hour, COUNT(*) as cnt
                   FROM parking_records WHERE DATE(entry_time)=DATE('now','localtime')
                   GROUP BY hour ORDER BY hour""")
    hourly_data = [{'hour': r[0], 'cnt': r[1]} for r in cur.fetchall()]

    cur.execute("""SELECT DATE(exit_time) as day, COALESCE(SUM(amount_due),0) as rev
                   FROM parking_records WHERE payment_status='paid'
                   AND exit_time >= datetime('now','-7 days','localtime')
                   GROUP BY DATE(exit_time) ORDER BY day""")
    weekly_revenue = [{'day': str(r[0]), 'rev': float(r[1])} for r in cur.fetchall()]

    cur.execute("""SELECT vehicle_type, COALESCE(SUM(amount_due),0) as rev, COUNT(*) as cnt
                   FROM parking_records WHERE payment_status='paid' AND DATE(exit_time)=DATE('now','localtime')
                   GROUP BY vehicle_type""")
    type_revenue = {r[0]: {'vehicle_type': r[0], 'rev': float(r[1]), 'cnt': r[2]} for r in cur.fetchall()}

    cur.execute("""SELECT CAST(strftime('%H', entry_time) AS INTEGER) as hour, COUNT(*) as cnt
                   FROM parking_records GROUP BY hour ORDER BY cnt DESC LIMIT 1""")
    peak = cur.fetchone()
    peak_hour = f"{peak[0]:02d}:00" if peak else 'N/A'

    cur.execute("SELECT COALESCE(AVG(duration_minutes),0) FROM parking_records WHERE duration_minutes IS NOT NULL")
    avg_duration = int(cur.fetchone()[0])

    cur.close(); conn.close()
    return render_template('dashboard.html',
        total_slots=total_slots, occupied=occupied, free=total_slots-occupied,
        occ_2w=occ_2w, occ_4w=occ_4w, total_2w=total_2w, total_4w=total_4w,
        today_revenue=round(float(today_rev),2), month_revenue=round(float(month_rev),2),
        total_vehicles=total_vehicles, active_records=active_records,
        hourly_data=hourly_data, weekly_revenue=weekly_revenue,
        type_revenue=type_revenue, peak_hour=peak_hour, avg_duration=avg_duration)


# ── Analytics ─────────────────────────────────────────────────────────────────

@app.route('/analytics')
@role_required('admin')
def analytics():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""SELECT vehicle_type,
                          COALESCE(SUM(amount_due),0) as total_rev,
                          COUNT(*) as total_visits,
                          COALESCE(AVG(duration_minutes),0) as avg_min
                   FROM parking_records WHERE payment_status='paid'
                   AND exit_time >= datetime('now','-30 days')
                   GROUP BY vehicle_type""")
    type_stats = {r[0]: {'vehicle_type':r[0],'total_rev':round(float(r[1]),2),'total_visits':r[2],'avg_min':int(r[3])} for r in cur.fetchall()}

    cur.execute("""SELECT DATE(exit_time) as day, COALESCE(SUM(amount_due),0) as rev, COUNT(*) as cnt
                   FROM parking_records WHERE payment_status='paid'
                   AND exit_time >= datetime('now','-30 days')
                   GROUP BY DATE(exit_time) ORDER BY day""")
    daily_30 = [{'day': str(r[0]), 'rev': round(float(r[1]),2), 'cnt': r[2]} for r in cur.fetchall()]

    cur.execute("""SELECT CAST(strftime('%H', entry_time) AS INTEGER) as hour, COUNT(*) as cnt
                   FROM parking_records GROUP BY hour ORDER BY hour""")
    peak_hours = [{'hour': r[0], 'cnt': r[1]} for r in cur.fetchall()]

    cur.execute("""SELECT payment_method, COUNT(*) as cnt, COALESCE(SUM(amount_due),0) as rev
                   FROM parking_records WHERE payment_status='paid'
                   GROUP BY payment_method ORDER BY cnt DESC""")
    payment_stats = [{'payment_method': r[0], 'cnt': r[1], 'rev': round(float(r[2]),2)} for r in cur.fetchall()]

    cur.execute("""SELECT vehicle_number, vehicle_type, COUNT(*) as visits,
                          COALESCE(SUM(amount_due),0) as total_paid
                   FROM parking_records GROUP BY vehicle_number, vehicle_type
                   ORDER BY visits DESC LIMIT 10""")
    frequent = rows_to_dicts(cur.fetchall())

    cur.execute("""SELECT strftime('%b %Y', exit_time) as month,
                          COALESCE(SUM(amount_due),0) as rev, COUNT(*) as visits
                   FROM parking_records WHERE payment_status='paid'
                   AND exit_time >= datetime('now','-6 months')
                   GROUP BY strftime('%Y-%m', exit_time) ORDER BY strftime('%Y-%m', exit_time)""")
    monthly = [{'month': r[0], 'rev': round(float(r[1]),2), 'visits': r[2]} for r in cur.fetchall()]

    cur.execute("""SELECT zone, vehicle_type,
                          SUM(is_occupied) as occ,
                          COUNT(*) as total
                   FROM parking_slots GROUP BY zone, vehicle_type ORDER BY zone""")
    zone_occ = [{'zone':r[0],'vehicle_type':r[1],'occ':r[2],'total':r[3]} for r in cur.fetchall()]

    cur.close(); conn.close()
    return render_template('analytics.html',
        type_stats=type_stats, daily_30=daily_30, peak_hours=peak_hours,
        payment_stats=payment_stats, frequent=frequent, monthly=monthly, zone_occ=zone_occ)


# ── Slot map ──────────────────────────────────────────────────────────────────

@app.route('/slot-map')
@login_required
def slot_map():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT ps.*, pr.vehicle_number, pr.owner_name, pr.entry_time
                   FROM parking_slots ps
                   LEFT JOIN parking_records pr ON ps.id=pr.slot_id AND pr.exit_time IS NULL
                   ORDER BY ps.zone, ps.slot_number""")
    slots = rows_to_dicts(cur.fetchall())
    cur.close(); conn.close()
    return render_template('slot_map.html',
        a_slots=[s for s in slots if s['zone']=='A'],
        b_slots=[s for s in slots if s['zone']=='B'])


# ── Entry ─────────────────────────────────────────────────────────────────────

@app.route('/entry', methods=['GET','POST'])
@role_required('admin','entry_staff')
def entry():
    conn = get_db()
    cur = conn.cursor()
    if request.method == 'POST':
        vehicle_number = request.form['vehicle_number'].upper().strip()
        vehicle_type   = request.form['vehicle_type']
        owner_name     = request.form.get('owner_name','').strip()
        owner_phone    = request.form.get('owner_phone','').strip()
        owner_email    = request.form.get('owner_email','').strip()
        slot_id        = request.form.get('slot_id','')

        if not valid_vehicle_number(vehicle_number):
            flash('Invalid vehicle number format. Use format like AP09AB1234.', 'danger')
        elif vehicle_type not in ('2-wheeler', '4-wheeler'):
            flash('Invalid vehicle type.', 'danger')
        elif not slot_id:
            flash('Please select a parking slot.', 'danger')
        else:
            cur.execute("SELECT id FROM parking_records WHERE vehicle_number=? AND exit_time IS NULL", (vehicle_number,))
            if cur.fetchone():
                flash(f'Vehicle {vehicle_number} is already parked!', 'warning')
            else:
                # Verify slot is free and matches the vehicle type
                cur.execute(
                    "SELECT id FROM parking_slots WHERE id=? AND vehicle_type=? AND is_occupied=0",
                    (slot_id, vehicle_type)
                )
                if not cur.fetchone():
                    flash('Selected slot is unavailable or wrong vehicle type.', 'danger')
                else:
                    cur.execute("""INSERT INTO parking_records
                        (vehicle_number, vehicle_type, owner_name, owner_phone, owner_email, slot_id, entry_staff_id)
                        VALUES (?,?,?,?,?,?,?)""",
                        (vehicle_number, vehicle_type, owner_name, owner_phone, owner_email, slot_id, current_user.id))
                    record_id = cur.lastrowid
                    cur.execute("UPDATE parking_slots SET is_occupied=1 WHERE id=?", (slot_id,))
                    conn.commit()
                    flash(f'Vehicle {vehicle_number} parked — Record #{record_id}', 'success')
                    cur.close(); conn.close()
                    return redirect(url_for('entry'))

    cur.execute("SELECT * FROM parking_slots WHERE is_occupied=0 ORDER BY zone, slot_number")
    free_slots = rows_to_dicts(cur.fetchall())
    cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                   JOIN parking_slots ps ON pr.slot_id=ps.id
                   WHERE pr.exit_time IS NULL ORDER BY pr.entry_time DESC LIMIT 15""")
    active = rows_to_dicts(cur.fetchall())
    cur.close(); conn.close()
    return render_template('entry.html', free_slots=free_slots, active=active)


@app.route('/api/free-slots/<vehicle_type>')
@login_required
def api_free_slots(vehicle_type):
    if vehicle_type not in ('2-wheeler', '4-wheeler'):
        abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, slot_code FROM parking_slots WHERE is_occupied=0 AND vehicle_type=? ORDER BY slot_number", (vehicle_type,))
    slots = [{'id': r[0], 'slot_code': r[1]} for r in cur.fetchall()]
    cur.close(); conn.close()
    return jsonify(slots)


# ── Exit / Checkout ───────────────────────────────────────────────────────────

@app.route('/exit', methods=['GET','POST'])
@role_required('admin','exit_staff')
def exit_vehicle():
    conn = get_db()
    cur = conn.cursor()
    record  = None
    qr_code = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'search':
            search         = request.form['search'].upper().strip()
            payment_method = request.form.get('payment_method', 'cash')
            cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                           JOIN parking_slots ps ON pr.slot_id=ps.id
                           WHERE pr.vehicle_number=? AND pr.exit_time IS NULL""", (search,))
            rec = row_to_dict(cur.fetchone())
            if not rec:
                flash(f'No active record found for "{search}"', 'warning')
            else:
                now = datetime.now()
                mins, amt = calc_amount(rec['entry_time'], now, rec['vehicle_type'])
                record = rec
                record['calc_duration']    = mins
                record['calc_amount']      = amt
                record['selected_payment'] = payment_method
                if payment_method == 'upi':
                    qr_code = generate_upi_qr(amt, rec['vehicle_number'])
        elif action == 'checkout':
            record_id      = int(request.form['record_id'])
            payment_method = request.form['payment_method']
            if payment_method not in ('cash', 'upi', 'card'):
                flash('Invalid payment method.', 'danger')
                cur.close(); conn.close()
                return redirect(url_for('exit_vehicle'))
            cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                           JOIN parking_slots ps ON pr.slot_id=ps.id WHERE pr.id=?""", (record_id,))
            rec = row_to_dict(cur.fetchone())
            if not rec or rec['exit_time']:
                flash('Record not found or already checked out.', 'danger')
                cur.close(); conn.close()
                return redirect(url_for('exit_vehicle'))
            now     = datetime.now()
            mins, amt = calc_amount(rec['entry_time'], now, rec['vehicle_type'])
            now_str = now.strftime('%Y-%m-%d %H:%M:%S')
            cur.execute("""UPDATE parking_records
                           SET exit_time=?, duration_minutes=?, amount_due=?,
                               payment_method=?, payment_status='paid', exit_staff_id=?
                           WHERE id=?""",
                (now_str, mins, amt, payment_method, current_user.id, record_id))
            cur.execute("UPDATE parking_slots SET is_occupied=0 WHERE id=?", (rec['slot_id'],))
            conn.commit()
            rec.update({'exit_time': now, 'duration_minutes': mins,
                        'amount_due': amt, 'payment_method': payment_method})
            send_email_receipt(rec)
            cur.close(); conn.close()
            flash('Checkout complete. Receipt emailed if address on file.', 'info')
            return redirect(url_for('bill', record_id=record_id))
    cur.close(); conn.close()
    return render_template('exit.html', record=record, qr_code=qr_code)


# ── Bill ──────────────────────────────────────────────────────────────────────

@app.route('/bill/<int:record_id>')
@login_required
def bill(record_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT pr.*, ps.slot_code,
                          eu.full_name as entry_staff_name,
                          xu.full_name as exit_staff_name
                   FROM parking_records pr
                   JOIN parking_slots ps ON pr.slot_id=ps.id
                   LEFT JOIN users eu ON pr.entry_staff_id=eu.id
                   LEFT JOIN users xu ON pr.exit_staff_id=xu.id
                   WHERE pr.id=?""", (record_id,))
    record = row_to_dict(cur.fetchone())
    cur.close(); conn.close()
    if not record:
        flash('Record not found.', 'danger')
        return redirect(url_for('dashboard'))
    qr_code = None
    if record['payment_method'] == 'upi':
        qr_code = generate_upi_qr(record['amount_due'], record['vehicle_number'])
    return render_template('bill.html', record=record, qr_code=qr_code)


# ── Admin: Users ──────────────────────────────────────────────────────────────

@app.route('/admin/users', methods=['GET','POST'])
@role_required('admin')
def admin_users():
    conn = get_db()
    cur = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            new_username = request.form['username'].strip()
            new_password = request.form['password']
            new_role     = request.form['role']
            new_fullname = request.form['full_name'].strip()
            if new_role not in ('admin', 'entry_staff', 'exit_staff'):
                flash('Invalid role.', 'danger')
            elif len(new_password) < 8:
                flash('Password must be at least 8 characters.', 'danger')
            else:
                try:
                    cur.execute(
                        "INSERT INTO users (username, password_hash, role, full_name, must_change_password) VALUES (?,?,?,?,?)",
                        (new_username, generate_password_hash(new_password), new_role, new_fullname, 1)
                    )
                    conn.commit()
                    flash(f"User '{new_username}' created. They must change password on first login.", 'success')
                except sqlite3.IntegrityError:
                    flash('Username already exists.', 'danger')
        elif action == 'delete':
            uid = int(request.form['user_id'])
            if uid == current_user.id:
                flash("You can't delete your own account.", 'warning')
            else:
                cur.execute("DELETE FROM users WHERE id=?", (uid,))
                conn.commit()
                flash('User deleted.', 'success')
    cur.execute("SELECT id, username, role, full_name, created_at FROM users ORDER BY id")
    users = rows_to_dicts(cur.fetchall())
    cur.close(); conn.close()
    return render_template('admin_users.html', users=users)


# ── Admin: Records ────────────────────────────────────────────────────────────

@app.route('/admin/records')
@role_required('admin')
def admin_records():
    conn     = get_db()
    cur      = conn.cursor()
    page     = max(1, int(request.args.get('page', 1)))
    per_page = 20
    offset   = (page - 1) * per_page
    search   = request.args.get('q', '').strip().upper()
    if search:
        cur.execute("SELECT COUNT(*) FROM parking_records WHERE vehicle_number LIKE ?", (f'%{search}%',))
        total = cur.fetchone()[0]
        cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                       JOIN parking_slots ps ON pr.slot_id=ps.id
                       WHERE pr.vehicle_number LIKE ?
                       ORDER BY pr.entry_time DESC LIMIT ? OFFSET ?""", (f'%{search}%', per_page, offset))
    else:
        cur.execute("SELECT COUNT(*) FROM parking_records")
        total = cur.fetchone()[0]
        cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                       JOIN parking_slots ps ON pr.slot_id=ps.id
                       ORDER BY pr.entry_time DESC LIMIT ? OFFSET ?""", (per_page, offset))
    records = rows_to_dicts(cur.fetchall())
    cur.close(); conn.close()
    pages = max(1, -(-total // per_page))
    return render_template('admin_records.html', records=records, page=page,
                           total=total, per_page=per_page, pages=pages, search=search)


# ── Admin: Rates (persisted in DB) ───────────────────────────────────────────

@app.route('/admin/rates', methods=['GET','POST'])
@role_required('admin')
def admin_rates():
    if request.method == 'POST':
        try:
            r2 = max(0.5, float(request.form['rate_2w']))
            r4 = max(0.5, float(request.form['rate_4w']))
            set_rates(r2, r4)
            flash('Rates updated successfully!', 'success')
        except ValueError:
            flash('Invalid rate values.', 'danger')
    rates = get_rates()
    return render_template('admin_rates.html', rates=rates)


# ── Admin: Email config ───────────────────────────────────────────────────────

@app.route('/admin/email-config')
@role_required('admin')
def admin_email_config():
    return render_template('admin_email.html',
        smtp_configured=bool(SMTP_USER and SMTP_PASSWORD),
        smtp_host=SMTP_HOST, smtp_port=SMTP_PORT,
        smtp_user=SMTP_USER if SMTP_USER else '(not configured)')


# ── Resend email receipt ──────────────────────────────────────────────────────

@app.route('/bill/<int:record_id>/resend-email', methods=['POST'])
@login_required
def resend_email(record_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT pr.*, ps.slot_code FROM parking_records pr
                   JOIN parking_slots ps ON pr.slot_id=ps.id WHERE pr.id=?""", (record_id,))
    rec = row_to_dict(cur.fetchone())
    cur.close(); conn.close()
    if rec and rec.get('owner_email'):
        send_email_receipt(rec)
        flash(f'Receipt queued for delivery to {rec["owner_email"]}.', 'success')
    else:
        flash('No email address on record.', 'warning')
    return redirect(url_for('bill', record_id=record_id))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, host='0.0.0.0')
