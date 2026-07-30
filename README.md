# ParkOS — Parking Lot Management System

## Tech Stack
- **Backend**: Flask (Python)
- **Database**: PostgreSQL (Supabase / local)
- **Auth**: Flask-Login + Werkzeug (hashed passwords)
- **QR Codes**: qrcode + Pillow
- **Charts**: Chart.js (CDN)
- **Fonts**: Syne + JetBrains Mono

---

## Roles & Access

| Role | Access |
|------|--------|
| **Admin** | Everything: Users, Records, Rates, Entry, Exit, Dashboard |
| **Entry Staff** | Vehicle Entry registration + Slot Map + Dashboard |
| **Exit Staff** | Vehicle Exit + Billing + QR Code + Dashboard |

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set environment variables
Create a `.env` file or set in your terminal:
```bash
export DATABASE_URL="postgresql://user:password@host/dbname"
export SECRET_KEY="your-secret-key-here"
```

### 3. Run the app
```bash
python app.py
```
The app auto-creates all tables and seeds demo users on first run.

---

## Demo Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| entry1 | entry123 | Entry Staff |
| exit1 | exit123 | Exit Staff |

---

## Parking Slots

- **Zone A** — A1 to A20 — 2-Wheelers (motorbikes, scooters)
- **Zone B** — B1 to B20 — 4-Wheelers (cars, SUVs)

---

## Billing Logic

- Minimum charge: 1 slot = 30 minutes
- 2-Wheeler: Rs. 10 / 30 min (configurable)
- 4-Wheeler: Rs. 20 / 30 min (configurable)
- Rates managed by Admin at `/admin/rates`

---

## Features

- Role-based access control (3 roles)
- Visual slot map with hover tooltips
- Vehicle entry with dynamic slot assignment
- Vehicle exit with bill calculation
- UPI QR code for digital payment
- Print bill (browser print dialog)
- Save as PDF (print to PDF)
- Admin analytics dashboard (Chart.js)
- User management (add/delete)
- Parking rates management
- Paginated records table
- Responsive dark UI

---

## Deployment on Render

1. Connect your GitHub repo
2. Set `DATABASE_URL` environment variable (Supabase PostgreSQL URL)
3. Set `SECRET_KEY` environment variable
4. Start command: `gunicorn app:app`
