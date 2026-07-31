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
import sqlite3
import socket
import os
from config_manager import config_mgr

# Load .env in development
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from mac_vendor_lookup import MacLookup

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
    # Incident Response (created by Flask scanner for auto-escalation)
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_incident_response (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            title TEXT,
            asset_name TEXT,
            ip_address TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New',
            source TEXT DEFAULT 'Scanner',
            notes TEXT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            acknowledged_at DATETIME,
            resolved_at DATETIME
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
import ipaddress

def _read_arp_table():
    """Parse 'arp -a' output and return {ip: mac} dict from the OS ARP cache."""
    found = {}
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            parts = line.split()
            # Windows: 'IP  MAC  type', Linux: 'IP  (MAC)  ...'
            if len(parts) >= 2:
                ip_candidate = parts[0].strip('()')
                mac_candidate = parts[1].strip('()') if len(parts) > 1 else ''
                # Basic validation
                if ip_candidate.count('.') == 3 and '-' in mac_candidate or ':' in mac_candidate:
                    found[ip_candidate] = mac_candidate.replace('-', ':').lower()
    except Exception as e:
        print(f"[arp-a] failed: {e}")
    return found


def _ping_sweep(network_str):
    """Ping every host in the subnet concurrently; return list of responding IPs."""
    try:
        net = ipaddress.ip_network(network_str, strict=False)
    except ValueError:
        return []

    # Limit to reasonable range to avoid huge subnets taking forever
    hosts = list(net.hosts())
    if len(hosts) > 254:
        hosts = hosts[:254]

    def _do_ping(ip):
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", str(ip)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return str(ip) if result.returncode == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(_do_ping, hosts))
    return [ip for ip in results if ip]


def discover(network):
    """Multi-method discovery: Scapy ARP → OS ARP table → ping sweep."""
    active_ips = []

    # --- Method 1: Scapy ARP scan (requires admin on Windows) ---
    try:
        arp_pkt = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether / arp_pkt, timeout=2, verbose=0)[0]
        for _, r in result:
            active_ips.append(r.psrc)
            mac_cache[r.psrc] = r.hwsrc
        if active_ips:
            print(f"[discover] Scapy ARP found {len(active_ips)} hosts")
            return active_ips
    except Exception as e:
        print(f"[discover] Scapy ARP failed (probably no admin): {e}")

    # --- Method 2: OS ARP table (passive, no privileges needed) ---
    arp_table = _read_arp_table()
    if arp_table:
        # Filter to only IPs inside the requested network
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip, mac in arp_table.items():
                try:
                    if ipaddress.ip_address(ip) in net:
                        active_ips.append(ip)
                        mac_cache[ip] = mac
                except ValueError:
                    pass
        except ValueError:
            # If network is invalid, just take everything from ARP table
            for ip, mac in arp_table.items():
                active_ips.append(ip)
                mac_cache[ip] = mac

    # --- Method 3: Ping sweep to find hosts not yet in ARP table ---
    print(f"[discover] Running ping sweep on {network} ...")
    pinged = _ping_sweep(network)
    for ip in pinged:
        if ip not in active_ips:
            active_ips.append(ip)
            # Try to get MAC from ARP table after ping
            if ip not in mac_cache:
                fresh = _read_arp_table()
                if ip in fresh:
                    mac_cache[ip] = fresh[ip]

    print(f"[discover] Total discovered before filtering: {len(active_ips)} hosts")
    return active_ips

# ---------- LOCAL INTERFACES AND GATEWAY DETECTION ----------
import socket

def get_interfaces():
    host_ips = set()
    virtual_ips = set()
    try:
        import psutil
        for iface, snics in psutil.net_if_addrs().items():
            iface_lower = iface.lower()
            is_virtual = any(v in iface_lower for v in ['virtualbox', 'vmware', 'hyper-v', 'wsl', 'loopback', 'veth'])
            for snic in snics:
                if snic.family == socket.AF_INET:
                    if is_virtual:
                        virtual_ips.add(snic.address)
                    else:
                        host_ips.add(snic.address)
    except Exception:
        pass
    try:
        host_ips.add(socket.gethostbyname(socket.gethostname()))
    except:
        pass
    virtual_ips.add('127.0.0.1')
    return host_ips, virtual_ips

HOST_IPS, VIRTUAL_IPS = get_interfaces()

def get_default_gateway():
    try:
        from scapy.all import conf
        if conf.route and conf.route.route("0.0.0.0"):
            return conf.route.route("0.0.0.0")[2]
    except Exception:
        pass
    return None

DEFAULT_GATEWAY = get_default_gateway()

def get_active_subnet():
    try:
        from scapy.all import conf
        if conf.route and conf.route.route("0.0.0.0"):
            _, active_ip, _ = conf.route.route("0.0.0.0")
            import psutil
            import socket
            for iface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET and snic.address == active_ip:
                        import ipaddress
                        net = ipaddress.IPv4Network(f"{active_ip}/{snic.netmask}", strict=False)
                        return str(net)
    except Exception:
        pass
    return "192.168.1.0/24"

def is_valid_ip(ip):
    if ip.endswith('.255') or ip.endswith('.0'):
        return False
    if ip.startswith('192.168.56.'):
        return False
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_loopback:
            return False
    except ValueError:
        return False
    return True



# ---------- PING ----------
def ping(ip):
    try:
        import platform, subprocess, re
        is_win = platform.system().lower() == "windows"
        param = "-n" if is_win else "-c"
        timeout_arg = ["-w", "1000"] if is_win else ["-W", "1"]
        result = subprocess.run(
            ["ping", param, "1"] + timeout_arg + [ip],
            capture_output=True,
            text=True,
            timeout=2.0
        )
        if result.returncode != 0:
            return False
            
        out_lower = result.stdout.lower()
        if "unreachable" in out_lower or "timed out" in out_lower or "failure" in out_lower:
            return False
            
        return "ttl=" in out_lower
    except Exception:
        return False


# ---------- TTL FOR OS GUESS ----------
def get_ttl(ip):
    try:
        from scapy.all import IP, ICMP, sr1
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if pkt and hasattr(pkt, 'ttl'):
            return pkt.ttl
    except:
        pass

    try:
        import platform, subprocess, re
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", "-w", "1000", ip], capture_output=True, text=True)
        match = re.search(r"TTL=(\d+)", result.stdout, re.IGNORECASE)
        if match:
            return int(match.group(1))
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
    if 53 in ports:
        return "DNS Server"
    
    infra_ports = [80, 443, 21, 22, 25, 67, 68, 3306, 139]
    if any(p in infra_ports for p in ports):
        return "Infrastructure Service"
        
    client_ports = [445, 3389, 5900]
    if any(p in client_ports for p in ports):
        return "Client Device"
        
    if 8080 in ports or 23 in ports:
        return "Gateway / Router"
        
    return "Unknown Device"


# ---------- FIREWALL INFERENCE ----------
def infer_firewall(ports):
    if ports is None or len(ports) == 0:
        return "Unavailable"
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
    config_mgr.load()
    l1 = config_mgr.get("alerts.alert_severity_levels.level_1_seconds", LEVEL_1)
    l2 = config_mgr.get("alerts.alert_severity_levels.level_2_seconds", LEVEL_2)
    l3 = config_mgr.get("alerts.alert_severity_levels.level_3_seconds", LEVEL_3)
    if seconds >= l3:
        return "LEVEL 3 🚨"
    elif seconds >= l2:
        return "LEVEL 2 ⚠️"
    elif seconds >= l1:
        return "LEVEL 1 ⚡"
    return "OK"

# ---------- MAC RESOLVER ----------
def get_mac_address(ip):
    mac = mac_cache.get(ip)
    if mac and mac != "Unknown":
        return mac

    try:
        from scapy.all import getmacbyip
        scapy_mac = getmacbyip(ip)
        if scapy_mac:
            mac_cache[ip] = scapy_mac
            return scapy_mac
    except:
        pass

    try:
        import subprocess
        arp_out = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in arp_out.splitlines():
            if ip in line:
                parts = line.split()
                if len(parts) >= 2 and ('-' in parts[1] or ':' in parts[1]):
                    found_mac = parts[1].replace('-', ':').lower()
                    mac_cache[ip] = found_mac
                    return found_mac
    except:
        pass

    return "Unavailable"


# ---------- NETWORK SCAN ----------
def scan_network(network):

    if not network or network.lower() in ['auto', 'default']:
        network = get_active_subnet()

    active_ips = discover(network)
    
    # Filter invalid/false positive IPs
    active_ips = [ip for ip in active_ips if is_valid_ip(ip)]

    now = datetime.utcnow()

    # Ensure we only include last_seen devices from the requested subnet
    # so we don't merge topologies from different subnets.
    try:
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        subnet_last_seen = {ip for ip in last_seen.keys() if ipaddress.ip_address(ip) in net}
    except ValueError:
        subnet_last_seen = set(last_seen.keys())

    all_ips = set(active_ips) | subnet_last_seen
    all_ips = {ip for ip in all_ips if is_valid_ip(ip)}

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

        # Overrides for classification
        if ip == DEFAULT_GATEWAY:
            role = "Gateway / Router"
        elif ip in HOST_IPS:
            role = "Host Machine"
        elif ip.endswith('.255'):
            role = "Broadcast Address"
        elif ip.startswith('192.168.56.') or ip in VIRTUAL_IPS:
            role = "Virtual Adapter"
        elif role == "Unknown Device" and len(ports) > 0:
            role = "Client Device"

        ttl = get_ttl(ip)
        os_guess = guess_os(ttl)
        firewall = infer_firewall(ports)

        mac = get_mac_address(ip)
        vendor = get_vendor(mac) if mac != "Unavailable" else "Unavailable"
        rogue_status = detect_rogue(ip, mac, vendor, role, ports)

        # Do not allow null or empty strings
        if ttl is None:
            ttl = "Unavailable"
        if not mac or mac == "Unknown":
            mac = "Unavailable"
        if not os_guess or os_guess == "Unknown":
            os_guess = "Unavailable"

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

    # Use max_workers=20 for checking the filtered IPs
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        devices = list(executor.map(get_device_info, all_ips))

    # Finally, remove None elements if any, and return
    return [d for d in devices if d]


# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("dashboard_new.html")


@app.route("/scan", methods=["POST"])
def scan():

    try:

        data = request.json or {}

        network = data.get("network")

        if not network or network.lower() in ['auto', 'default']:
            network = get_active_subnet()

        print(f"[*] Starting scan for: {network}")

        data = scan_network(network)

        print(f"[+] Scan complete. Found {len(data)} nodes.")

        return jsonify(data)

    except Exception as e:

        print(f"[!] Scan error: {str(e)}")

        import traceback
        traceback.print_exc()

        return jsonify({"error": str(e)}), 500


def send_webhook_alert(webhook_url, subject, message, severity, sender):
    import urllib.request
    import json
    
    # Determine color
    color_hex = "#ef4444" if severity in ["Critical", "High"] else ("#f5a623" if severity == "Medium" else "#339933")
    color_dec = int(color_hex.replace("#", ""), 16)
    
    payload = {}
    url_lower = webhook_url.lower()
    
    if "discord.com" in url_lower or "discordapp.com" in url_lower:
        # Discord format
        payload = {
            "embeds": [
                {
                    "title": f"[{severity}] {subject}",
                    "description": message,
                    "color": color_dec,
                    "fields": [
                        {"name": "Severity", "value": severity, "inline": True},
                        {"name": "Sender", "value": sender, "inline": True}
                    ]
                }
            ]
        }
    elif "slack.com" in url_lower:
        # Slack format
        payload = {
            "attachments": [
                {
                    "title": f"[{severity}] {subject}",
                    "text": message,
                    "color": color_hex,
                    "fields": [
                        {"title": "Severity", "value": severity, "short": True},
                        {"title": "Sender", "value": sender, "short": True}
                    ]
                }
            ]
        }
    elif "office.com" in url_lower or "msteams" in url_lower or "webhook.office.com" in url_lower or "incomingwebhook" in url_lower:
        # Teams Office 365 MessageCard
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color_hex.replace("#", ""),
            "summary": f"[{severity}] {subject}",
            "sections": [{
                "activityTitle": f"[{severity}] {subject}",
                "activitySubtitle": f"Sender: {sender}",
                "facts": [
                    {"name": "Severity", "value": severity},
                    {"name": "Sender", "value": sender}
                ],
                "text": message
            }]
        }
    else:
        # Generic payload
        payload = {
            "text": f"[{severity}] {subject}\n\nSeverity: {severity}\nSender: {sender}\n\n{message}",
            "content": f"**[{severity}] {subject}**\n\n**Severity:** {severity}\n**Sender:** {sender}\n\n{message}"
        }
        
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "MonitorOS-Webhook"}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        response.read()


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
        is_test = data.get("is_test", False)
        status = "Sent"

        config_mgr.load()

        if is_test:
            if alert_type == "Webhook":
                if not webhook_url:
                    webhook_url = config_mgr.get("alerts.discord_webhook_url") or config_mgr.get("alerts.slack_webhook_url") or config_mgr.get("alerts.teams_webhook_url")
                if webhook_url:
                    try:
                        send_webhook_alert(webhook_url, subject, message, severity, sender)
                        return jsonify({"success": True, "message": "Test webhook alert sent successfully!"})
                    except Exception as e:
                        return jsonify({"error": f"Webhook test failed: {str(e)}"}), 400
                else:
                    return jsonify({"error": "No Webhook URL configured in settings."}), 400
            else:
                return jsonify({"error": "Invalid test alert configuration"}), 400

        # Fallback webhook
        if alert_type == "Webhook" and not webhook_url:
            webhook_url = config_mgr.get("alerts.discord_webhook_url") or config_mgr.get("alerts.slack_webhook_url") or config_mgr.get("alerts.teams_webhook_url")

        conn = get_db()
        c = conn.cursor()
        c.execute('''
            INSERT INTO app_alerts (sender, receiver, severity, subject, message, alert_type, webhook_url, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (sender, receiver, severity, subject, message, alert_type, webhook_url, status))
        alert_id = c.lastrowid

        if not is_test:
            now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
            c.execute('''
                INSERT INTO network_app_alertevent (
                    alert_type, severity, asset_name, ip_address, message, status,
                    created_at, downtime_duration, alert_source, occurrence_count,
                    suppression_count, first_detected, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_type or 'Manual',
                severity or 'Info',
                'N/A',
                None,
                f"Subject: {subject}\n\n{message}" if subject else message,
                'Active',
                now_str,
                '',
                'Manual',
                1,
                0,
                now_str,
                now_str
            ))

        conn.commit()
        conn.close()

        log_security_event("ALERT_SENT", f"{alert_type} alert sent by {sender} with severity {severity}")

        if alert_type == "Email" and receiver:
            # ---------- EMAIL CONFIGURATION ----------
            SMTP_SERVER = config_mgr.get("alerts.smtp_server", "smtp.gmail.com")
            SMTP_PORT = config_mgr.get("alerts.smtp_port", 587)
            SENDER_EMAIL = config_mgr.get("alerts.email_sender", "priyanshupri25@gmail.com")
            SENDER_PASSWORD = config_mgr.get("alerts.email_password", "kygfclwiebnaxpqn")
            # -----------------------------------------
            msg_email = MIMEMultipart('alternative')
            msg_email['Subject'] = f"[{severity}] {subject}"
            msg_email['From'] = f"Monitor OS Alert <{SENDER_EMAIL}>"
            msg_email['To'] = receiver
            
            # Simple fallback
            msg_email.attach(MIMEText(f"Severity: {severity}\n\n{message}", 'plain'))
            
            # Attractive HTML template
            color = "#ef4444" if severity in ["Critical", "High"] else ("#f5a623" if severity == "Medium" else "#339933")
            html_content = f"""
            <html>
                <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #08111f; padding: 40px 20px; text-align: left; margin: 0;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #111923; border: 1px solid #1e293b; border-top: 4px solid {color}; border-radius: 12px; padding: 35px; box-shadow: 0 10px 30px rgba(0,0,0,0.8);">
                        <h2 style="color: {color}; margin-top: 0; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid #1e293b; padding-bottom: 15px;">Monitor OS Alert</h2>
                        
                        <div style="margin-top: 20px;">
                            <div style="display: inline-block; padding: 5px 15px; border-radius: 20px; font-size: 13px; font-weight: bold; background: rgba(255,255,255,0.05); color: {color}; border: 1px solid {color}; margin-bottom: 20px; text-transform: uppercase;">
                                {severity} Severity
                            </div>
                            
                            <h3 style="color: #ffffff; font-size: 18px; margin-bottom: 20px;">{subject}</h3>
                            
                            <div style="background-color: rgba(255, 255, 255, 0.02); border: 1px solid #1e293b; padding: 20px; border-radius: 8px; color: #e2e8f0; line-height: 1.6; white-space: pre-wrap; font-size: 15px;">{message}</div>
                        </div>

                        <div style="margin-top: 30px; font-size: 13px; color: #64748b; border-top: 1px solid #1e293b; padding-top: 15px;">
                            <strong>Sender:</strong> {sender}<br>
                            <strong>Generated:</strong> Manual Alert Dispatch<br><br>
                            This is an automated notification from the Network Security Monitoring System.
                        </div>
                    </div>
                </body>
            </html>
            """
            msg_email.attach(MIMEText(html_content, 'html'))
            
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg_email)
            server.quit()
        elif alert_type == "Webhook" and webhook_url:
            try:
                send_webhook_alert(webhook_url, subject, message, severity, sender)
            except Exception as e:
                conn = get_db()
                c = conn.cursor()
                c.execute('UPDATE app_alerts SET status = ? WHERE id = ?', ("Failed", alert_id))
                conn.commit()
                conn.close()
                raise e

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

@app.route("/api/broadcast_messages/<int:msg_id>", methods=["DELETE"])
def delete_broadcast_message(msg_id):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM app_broadcast_messages WHERE id = ?", (msg_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
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
        "mac": "Unavailable",
        "vendor": "Unavailable",
        "hostname": "Unavailable",
        "status": "OFFLINE",
        "open_ports": [],
        "os": "Unavailable",
        "last_seen": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "ping_status": "Failed",
        "threat_severity": "Low",
        "active_services": []
    }

    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        row = c.execute('SELECT * FROM network_app_device WHERE ip_address = ?', (ip,)).fetchone()
        conn.close()

        if row:
            details["mac"] = row["mac_address"] if row["mac_address"] and row["mac_address"] != "Unknown" else "Unavailable"
            details["status"] = row["status"]
            if row["status"] == "ACTIVE":
                details["ping_status"] = "Success"
            
            import ast
            try:
                ports = ast.literal_eval(row["ports"])
                details["open_ports"] = ports
            except:
                details["open_ports"] = []
                
            details["last_seen"] = row["last_seen"]
            
            details["os"] = guess_os(get_ttl(ip)) or "Unavailable"
            details["vendor"] = get_vendor(details["mac"]) if details["mac"] != "Unavailable" else "Unavailable"
            
            common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}
            for port in details["open_ports"]:
                if port in common_ports:
                    details["active_services"].append(common_ports[port])
                    
            if 22 in details["open_ports"] or 23 in details["open_ports"] or 3389 in details["open_ports"]:
                details["threat_severity"] = "Medium"
            if 23 in details["open_ports"]:
                details["threat_severity"] = "High"

    except Exception as e:
        print("DB error in device_details:", e)

    try:
        import socket
        host = socket.gethostbyaddr(ip)
        details["hostname"] = host[0]
    except:
        pass

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
        config_mgr.load()
        SMTP_SERVER = config_mgr.get("alerts.smtp_server", "smtp.gmail.com")
        SMTP_PORT = config_mgr.get("alerts.smtp_port", 587)
        SENDER_EMAIL = config_mgr.get("alerts.email_sender", "priyanshupri25@gmail.com")
        SENDER_PASSWORD = config_mgr.get("alerts.email_password", "kygfclwiebnaxpqn")
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