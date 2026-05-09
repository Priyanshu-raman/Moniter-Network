# 🛡️ Network Monitor OS

A professional **Cybersecurity Network Monitoring Dashboard** built with a Django + Flask hybrid architecture. Features a premium dark neon "liquid glass" UI for real-time network visibility, device intelligence scanning, multi-channel alerts, and secure user registration.

Developed by **Srida IT Consulting & Service (OPC) Pvt Ltd**

---

## ✨ Features

- 🔍 **Network Scanner** — Discover all devices on your subnet with real-time scanning
- 💻 **Device Intelligence Panel** — Click any device to see live OS, open ports, services & threat severity
- 🗺️ **Network Map** — Interactive Cytoscape.js topology visualization grouped by subnet zones
- 🚨 **Multi-Channel Alert System** — Send Email, Broadcast, and Webhook (Discord/Slack/Teams) alerts
- 📊 **Security Audit Logs** — Full login/logout/failed-attempt event tracking with pagination
- 👤 **User Profile Management** — Dedicated profile editing with account management
- ⚙️ **Network Settings** — Configurable IP ranges, scan intervals, and IT contact directory
- 🔐 **OTP Email Verification** — Secure 6-digit OTP sent via Gmail SMTP on registration

---

## 🛠️ Tech Stack

| Layer     | Technology                        |
|-----------|-----------------------------------|
| Frontend  | HTML5, CSS3 (Liquid Glass UI), JS |
| Backend   | Django 4.x (main), Flask 3.x (API proxy) |
| Database  | SQLite                            |
| Network   | Scapy, python-nmap, socket        |
| Email     | smtplib (Gmail SMTP)              |
| Icons     | Lucide Icons                      |
| Map       | Cytoscape.js                      |

---

## 🚀 Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/monitor-os.git
cd monitor-os
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Email (for OTP)
In `app.py`, update the email credentials inside the `send_otp` function:
```python
SENDER_EMAIL = "your_gmail@gmail.com"
SENDER_PASSWORD = "your_16_char_app_password"
```
> ⚠️ Use a [Google App Password](https://myaccount.google.com/apppasswords), NOT your regular Gmail password.

### 4. Apply Django migrations
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 5. Run Django server
```bash
python manage.py runserver
```

### 6. Run Flask API proxy (in a separate terminal)
```bash
python app.py
```

Visit: **http://localhost:8080**

---

## 🔒 Security Notes

- `db.sqlite3` is excluded from this repository (contains user data)
- Never commit your `SENDER_PASSWORD` or any credentials to GitHub
- All OTPs expire after **5 minutes**

---

## 📄 License

MIT License — Free to use with attribution.

---

*Network Monitor Security Team — Srida IT Consulting & Service (OPC) Pvt Ltd*
