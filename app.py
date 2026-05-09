from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import nmap
import subprocess
import platform
from datetime import datetime, timedelta
import concurrent.futures
import threading
import json
# import sqlite3from mac_vendor_lookup import MacLookup
import sqlite3
from mac_vendor_lookup import MacLookup
import socket

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from Django frontend

def get_db():
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # Alerts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            severity TEXT,
            subject TEXT,
            message TEXT,
            alert_type TEXT,
            webhook_url TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )
    ''')
    # Broadcast Notes
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_broadcast_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_title TEXT,
            incident_id TEXT,
            assigned_to TEXT,
            severity TEXT,
            status TEXT,
            notes TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Broadcast Messages
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_broadcast_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT,
            sender TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            incident_id TEXT,
            status TEXT
        )
    ''')
    # Security Logs integration
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # OTP Verification
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_otp (
            email TEXT PRIMARY KEY,
            otp TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_security_event(event_type, description):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO app_security_logs (event_type, description) VALUES (?, ?)', (event_type, description))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Error logging security event:", e)


# ---------- ALERT LEVELS ----------
LEVEL_1 = 30 * 60
LEVEL_2 = 2 * 60 * 60
LEVEL_3 = 6 * 60 * 60

# ---------- STORAGE ----------
last_seen = {}
mac_cache = {}
vendor_cache = {}

lock = threading.Lock()

# ---------- LOAD TRUSTED DEVICES ----------
try:
    with open("trusted_devices.json") as f:
        trusted_devices = json.load(f)
except:
    trusted_devices = {}

# ---------- MAC VENDOR LOOKUP ----------
mac_lookup = MacLookup()

try:
    mac_lookup.update_vendors()
    print("[+] MAC vendor database updated")
except:
    print("[!] MAC vendor database already exists")

# ---------- MAC VENDOR DETECTION ----------
def get_vendor(mac):

    if not mac or mac == "Unknown":
        return "Unknown Vendor"

    if mac in vendor_cache:
        return vendor_cache[mac]

    try:
        vendor = mac_lookup.lookup(mac)
    except:
        vendor = "Unknown Vendor"

    vendor_cache[mac] = vendor
    return vendor


# ---------- NETWORK DISCOVERY ----------
def discover(network):

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    active_ips = []

    for _, r in result:

        active_ips.append(r.psrc)
        mac_cache[r.psrc] = r.hwsrc

    return active_ips


# ---------- PING ----------
def ping(ip):

    param = "-n" if platform.system().lower() == "windows" else "-c"

    return subprocess.call(
        ["ping", param, "1", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0


# ---------- TTL FOR OS GUESS ----------
def get_ttl(ip):

    try:

        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)

        if pkt:
            return pkt.ttl

    except:
        pass

    return None


# ---------- OS GUESS ----------
def guess_os(ttl):

    if ttl is None:
        return "Unknown"

    if ttl <= 64:
        return "Linux / Unix"

    elif ttl <= 128:
        return "Windows"

    elif ttl <= 255:
        return "Network Device"

    return "Unknown"


# ---------- PORT SCAN ----------
def scan_ports(ip):

    nm = nmap.PortScanner()

    ports = []

    common_ports = "21,22,23,25,53,67,68,80,110,135,139,143,443,445,3306,3389,5900,8080"

    try:

        nm.scan(ip, common_ports, arguments="-T4 --open")

        if ip in nm.all_hosts():

            for proto in nm[ip].all_protocols():

                for p in nm[ip][proto]:
                    ports.append(p)

    except Exception as e:
        print(f"Scan error for {ip}: {e}")

    return ports


# ---------- ROLE DETECTION ----------
def guess_role(ports):

    if 80 in ports and 443 in ports:
        return "Web Server"

    if 21 in ports:
        return "FTP Server"

    if 22 in ports:
        return "Linux Server"

    if 23 in ports:
        return "Telnet Device"

    if 25 in ports:
        return "Mail Server"

    if 53 in ports:
        return "DNS Server"

    if 67 in ports or 68 in ports:
        return "DHCP Server"

    if 445 in ports:
        return "Windows PC"

    if 3389 in ports:
        return "Remote Desktop PC"

    if 3306 in ports:
        return "Database Server"

    if 5900 in ports:
        return "VNC Device"

    if 8080 in ports:
        return "Router / Proxy"

    if 139 in ports:
        return "NAS / File Server"

    return "Client Device"


# ---------- FIREWALL INFERENCE ----------
def infer_firewall(ports):

    if len(ports) == 0:
        return "Possible Firewall"

    return "Open"


# ---------- ROGUE DEVICE DETECTION ----------
def detect_rogue(ip, mac, vendor, role, ports):

    if ip in trusted_devices:
        return "Trusted"

    if vendor == "Unknown Vendor":
        return "Suspicious Vendor"

    dangerous_ports = [23, 21]

    if any(p in dangerous_ports for p in ports):
        return "Dangerous Service"

    if "Router" in role and ip not in trusted_devices:
        return "Possible Rogue Router"

    return "Normal"


# ---------- ALERT SYSTEM ----------
def get_alert(seconds):

    if seconds >= LEVEL_3:
        return "LEVEL 3 🚨"

    elif seconds >= LEVEL_2:
        return "LEVEL 2 ⚠️"

    elif seconds >= LEVEL_1:
        return "LEVEL 1 ⚡"

    return "OK"


# ---------- NETWORK SCAN ----------
def scan_network(network):

    active_ips = discover(network)

    now = datetime.now()

    all_ips = set(active_ips) | set(last_seen.keys())

    def get_device_info(ip):

        active = ip in active_ips and ping(ip)

        if active:

            with lock:
                last_seen[ip] = now

            status = "ACTIVE"
            inactive_duration = "0"

            ports = scan_ports(ip)

            alert = "OK"

        else:

            with lock:
                if ip not in last_seen:
                    last_seen[ip] = now

                seconds = (now - last_seen[ip]).total_seconds()

            status = "INACTIVE"
            inactive_duration = str(timedelta(seconds=int(seconds)))
            alert = get_alert(seconds)

            ports = []

        role = guess_role(ports)

        ttl = get_ttl(ip)

        os_guess = guess_os(ttl)

        firewall = infer_firewall(ports)

        mac = mac_cache.get(ip, "Unknown")

        vendor = get_vendor(mac)

        rogue_status = detect_rogue(ip, mac, vendor, role, ports)

        return {
            "ip": ip,
            "status": "ACTIVE" if status == "ACTIVE" else "OFFLINE",
            "inactive": inactive_duration,
            "alert": alert,
            "ports": ports,
            "role": role,
            "os": os_guess,
            "ttl": ttl,
            "mac": mac,
            "vendor": vendor,
            "firewall": firewall,
            "rogue": rogue_status
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        devices = list(executor.map(get_device_info, all_ips))

    return devices


# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("dashboard_new.html")


@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.json or {}

        network = data.get("network")

        if not network:
            return jsonify({"error": "No network provided"}), 400

        print(f"[*] Starting scan for: {network}")

        data = scan_network(network)

        print(f"[+] Scan complete. Found {len(data)} nodes.")

        return jsonify(data)

    except Exception as e:

        print(f"[!] Scan error: {str(e)}")

        import traceback
        traceback.print_exc()

        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts", methods=["POST"])
def create_alert():
    try:
        data = request.json or {}
        alert_type = data.get("alert_type")
        severity = data.get("severity")
        subject = data.get("subject")
        message = data.get("message")
        sender = data.get("sender")
        receiver = data.get("receiver")
        webhook_url = data.get("webhook_url")
        status = "Sent"

        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO app_alerts (sender, receiver, severity, subject, message, alert_type, webhook_url, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (sender, receiver, severity, subject, message, alert_type, webhook_url, status))
        conn.commit()
        conn.close()

        log_security_event("ALERT_SENT", f"{alert_type} alert sent by {sender} with severity {severity}")

        return jsonify({"success": True, "message": "Alert created successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/broadcast_notes", methods=["POST"])
def create_broadcast_note():
    try:
        data = request.json or {}
        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO app_broadcast_notes (incident_title, incident_id, assigned_to, severity, status, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data.get('incident_title'), data.get('incident_id'), data.get('assigned_to'),
              data.get('severity'), data.get('status'), data.get('notes')))
        conn.commit()
        conn.close()

        log_security_event("NOTE_ADDED", f"Note added for incident {data.get('incident_id')}")

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/broadcast_messages", methods=["GET", "POST"])
def handle_broadcast_messages():
    if request.method == "POST":
        try:
            data = request.json or {}
            conn = get_db()
            c = conn.cursor()
            c.execute('''
                INSERT INTO app_broadcast_messages (severity, sender, message, incident_id, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (data.get('severity'), data.get('sender'), data.get('message'),
                  data.get('incident_id'), data.get('status')))
            conn.commit()
            conn.close()

            log_security_event("BROADCAST_CREATED", f"Broadcast created by {data.get('sender')} for incident {data.get('incident_id')}")

            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        try:
            conn = get_db()
            c = conn.cursor()
            # Newest first
            messages = c.execute('SELECT * FROM app_broadcast_messages ORDER BY timestamp DESC').fetchall()
            conn.close()
            return jsonify([dict(m) for m in messages])
        except Exception as e:
            return jsonify({"error": str(e)}), 500

import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

@app.route("/api/device_details", methods=["GET"])
def device_details():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400

    details = {
        "ip": ip,
        "mac": "Unknown",
        "vendor": "Unknown",
        "hostname": "Unknown",
        "status": "OFFLINE",
        "open_ports": [],
        "os": "Unknown",
        "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ping_status": "Failed",
        "threat_severity": "Low",
        "active_services": []
    }

    # Ping scan
    try:
        ping_resp = subprocess.run(["ping", "-n", "1", "-w", "1000", ip], capture_output=True, text=True)
        if "TTL=" in ping_resp.stdout or "ttl=" in ping_resp.stdout.lower():
            details["ping_status"] = "Success"
            details["status"] = "ACTIVE"
            if "TTL=128" in ping_resp.stdout: details["os"] = "Windows"
            elif "TTL=64" in ping_resp.stdout: details["os"] = "Linux/Mac"
    except:
        pass

    # Hostname detection
    try:
        host = socket.gethostbyaddr(ip)
        details["hostname"] = host[0]
    except:
        details["hostname"] = "Unknown"

    # Quick Port Scan (Common ports)
    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        result = sock.connect_ex((ip, port))
        if result == 0:
            details["open_ports"].append(port)
            details["active_services"].append(service)
        sock.close()

    # Threat Severity heuristic
    if 22 in details["open_ports"] or 23 in details["open_ports"] or 3389 in details["open_ports"]:
        details["threat_severity"] = "Medium"
    if 23 in details["open_ports"]:
        details["threat_severity"] = "High"

    return jsonify(details)

@app.route("/api/send_otp", methods=["POST"])
def send_otp():
    data = request.json or {}
    email = data.get("email")
    if not email: return jsonify({"error": "Email required"}), 400
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT email FROM auth_user WHERE email = ?', (email,))
        if c.fetchone():
            return jsonify({"error": "Email already registered."}), 400
    except:
        pass

    otp_code = str(random.randint(100000, 999999))
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO app_otp (email, otp) VALUES (?, ?)', (email, otp_code))
        conn.commit()
        conn.close()

        # ---------- EMAIL CONFIGURATION ----------
        # Credentials are loaded from the .env file (not stored in code)
        SMTP_SERVER = "smtp.gmail.com"
        SMTP_PORT = 587
        SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "your.email@gmail.com")
        SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "")
        # -----------------------------------------

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"{otp_code} is your Monitor OS verification code"
        msg['From'] = f"Monitor OS <{SENDER_EMAIL}>"
        msg['To'] = email

        html_content = f"""
        <html>
            <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #090e11; padding: 40px 20px; text-align: left;">
                <div style="max-width: 550px; margin: 0 auto; background-color: #111923; border: 1px solid #339933; border-radius: 12px; padding: 35px; box-shadow: 0 10px 30px rgba(0,0,0,0.8);">
                    <p style="color: #ffffff; font-size: 16px; margin-bottom: 20px;">Dear User,</p>
                    
                    <p style="color: #94a3b8; font-size: 15px; margin-bottom: 20px; line-height: 1.6;">
                        Thank you for registering with Network Monitor Security System by Srida IT Consulting & Service (OPC) Pvt Ltd.
                    </p>
                    
                    <p style="color: #94a3b8; font-size: 15px; margin-bottom: 30px; line-height: 1.6;">
                        To complete your account verification process, please use the One-Time Password (OTP) provided below:
                    </p>
                    
                    <div style="background-color: rgba(51, 153, 51, 0.1); border-left: 4px solid #339933; padding: 20px; margin-bottom: 30px;">
                        <span style="color: #94a3b8; font-size: 16px;">OTP Code: </span>
                        <span style="font-size: 28px; font-weight: bold; letter-spacing: 4px; color: #ffffff; margin-left: 10px;">{otp_code}</span>
                    </div>

                    <p style="color: #64748b; font-size: 14px; margin-bottom: 15px;">
                        This OTP is valid for the next 5 minutes. Please do not share this code with anyone for security reasons.
                    </p>
                    <p style="color: #64748b; font-size: 14px; margin-bottom: 40px;">
                        If you did not request this verification, please ignore this email.
                    </p>

                    <div style="border-top: 1px solid #1e293b; padding-top: 20px;">
                        <p style="color: #ffffff; font-size: 15px; margin: 0 0 5px 0;">Regards,</p>
                        <p style="color: #339933; font-weight: bold; font-size: 15px; margin: 0 0 5px 0;">Network Monitor Security Team</p>
                        <p style="color: #64748b; font-size: 13px; margin: 0;">Srida IT Consulting & Service (OPC) Pvt Ltd</p>
                    </div>
                </div>
            </body>
        </html>
        """
        msg.attach(MIMEText(html_content, 'html'))

        # Only attempt to send if credentials are provided
        if SENDER_EMAIL != "your.email@gmail.com":
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, email, msg.as_string())
            server.quit()
            print(f"[SMTP] Successfully sent real OTP email to {email}")
        else:
            print(f"[SMTP Warning] Credentials not set! Mock OTP: {otp_code}")
        
        return jsonify({"success": True, "message": "OTP sent successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json or {}
    email = data.get("email")
    otp = data.get("otp")
    if not email or not otp: return jsonify({"error": "Email and OTP required"}), 400
    
    conn = get_db()
    c = conn.cursor()
    row = c.execute('SELECT otp, timestamp FROM app_otp WHERE email = ?', (email,)).fetchone()
    conn.close()
    
    if row:
        stored_time = datetime.strptime(row['timestamp'], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() - stored_time > timedelta(minutes=5):
            return jsonify({"error": "OTP expired"}), 400
        if row['otp'] == otp:
            return jsonify({"success": True})
    return jsonify({"error": "Invalid OTP"}), 400

# ---------- START SERVER ----------
if __name__ == "__main__":
    app.run(debug=True)