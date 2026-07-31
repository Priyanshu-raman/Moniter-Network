import os
import json
import urllib.request
import urllib.error

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt

from .models import Device, LoginActivity, UserProfile, ITContact, GlobalSettings, Asset, Notification, AlertEvent, Incident, Vulnerability, VULN_SEVERITY_CHOICES, VULN_STATUS_CHOICES, ScanSession
from .forms  import ITContactForm, GlobalSettingsForm, CustomUserCreationForm, AssetForm
from config_manager import config_mgr


# ─── helpers ────────────────────────────────────────────────────────────────

def _get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _get_or_create_profile(user):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile

@login_required(login_url='login')
def broadcast_view(request):
    profile = _get_or_create_profile(request.user)
    return render(request, 'broadcast.html', {
        'username': request.user.username,
        'email': request.user.email,
        'avatar_url': profile.get_avatar_url(),
    })

# ─── Subnet → zone mapping utility ──────────────────────────────────────────

SUBNET_ZONES = {
    '192.168.1': {'name': 'SOC',              'color': '#33cc66'},
    '192.168.2': {'name': 'Admin/Management', 'color': '#3b82f6'},
    '192.168.3': {'name': 'Corporate',        'color': '#f59e0b'},
    '192.168.4': {'name': 'Servers/DMZ',      'color': '#ef4444'},
}

DEFAULT_ZONE = {'name': 'Other', 'color': '#8b5cf6'}


def _get_zone(ip: str) -> dict:
    """Return zone metadata for a given IP address."""
    prefix = '.'.join(ip.split('.')[:3])
    return SUBNET_ZONES.get(prefix, {**DEFAULT_ZONE, 'prefix': prefix})


# ── device-type classifier ───────────────────────────────────────────────────

ROLE_TO_TYPE = {
    'Web Server':        'Server',
    'Linux Server':      'Server',
    'Mail Server':       'Server',
    'DNS Server':        'Server',
    'DHCP Server':       'Server',
    'FTP Server':        'Server',
    'NAS / File Server': 'Server',
    'Database Server':   'Database',
    'Windows PC':        'PC',
    'Remote Desktop PC': 'Workstation',
    'Router / Proxy':    'Router',
    'Telnet Device':     'Router',
    'VNC Device':        'PC',
    'Client Device':     'PC',
}


def _role_to_device_type(role: str) -> str:
    """Map a Flask role string to one of the 8 Django device_type choices."""
    if not role:
        return 'Unknown'
    
    # Exact lookup in mapping first
    mapped = ROLE_TO_TYPE.get(role)
    if mapped:
        return mapped
        
    # Heuristics (case-insensitive checks)
    r_lower = role.lower()
    if 'gateway' in r_lower:
        return 'Gateway'
    if 'router' in r_lower:
        return 'Router'
    if 'switch' in r_lower:
        return 'Switch'
    if 'database' in r_lower or 'db' in r_lower:
        return 'Database'
    if 'server' in r_lower or 'infrastructure' in r_lower:
        return 'Server'
    if 'workstation' in r_lower:
        return 'Workstation'
    if 'pc' in r_lower or 'client' in r_lower or 'host' in r_lower or 'machine' in r_lower:
        return 'PC'
    if 'mobile' in r_lower or 'phone' in r_lower or 'tablet' in r_lower:
        return 'Mobile'
        
    return 'Unknown'


# ─── API: scan proxy (forwards to Flask, saves to Django DB) ─────────────────

def dispatch_notification_via_flask(alert_type, severity, subject, message, receiver=None, webhook_url=None):
    import sys
    if 'test' in sys.argv:
        return
    try:
        flask_url = 'http://127.0.0.1:5000/api/alerts'
        payload = {
            'alert_type': alert_type,
            'severity': severity,
            'subject': subject,
            'message': message,
            'sender': 'Scanner',
            'receiver': receiver,
            'webhook_url': webhook_url,
            'is_test': False
        }
        req = urllib.request.Request(
            flask_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception as e:
        print(f"Failed to dispatch flask alert: {e}")

def dispatch_alerts(alert):
    subject = f"⚠️ DEVICE OFFLINE: {alert.ip_address}"
    message = (
        f"Alert: {alert.message}\n"
        f"Severity: {alert.severity}\n"
        f"Asset Name: {alert.asset_name}\n"
        f"IP Address: {alert.ip_address}\n"
        f"Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    # Send Dashboard notification
    Notification.objects.create(
        title=subject,
        message=message,
        level=alert.severity
    )
    
    # Send Webhooks
    config_mgr.load()
    discord_url = config_mgr.get("alerts.discord_webhook_url")
    slack_url = config_mgr.get("alerts.slack_webhook_url")
    teams_url = config_mgr.get("alerts.teams_webhook_url")
    for url in [discord_url, slack_url, teams_url]:
        if url:
            dispatch_notification_via_flask('Webhook', alert.severity, subject, message, webhook_url=url)
            
    # Send Email
    email_key = "level_1_email"
    if alert.severity == "Critical":
        email_key = "level_3_email"
    elif alert.severity == "High":
        email_key = "level_2_email"
    recipient = config_mgr.get(f"alerts.email_recipients.{email_key}")
    if recipient:
        dispatch_notification_via_flask('Email', alert.severity, subject, message, receiver=recipient)

def dispatch_recovery(alert):
    subject = f"🟢 DEVICE RECOVERED: {alert.ip_address}"
    message = (
        f"Recovery: Device {alert.ip_address} ({alert.asset_name}) is back ONLINE.\n"
        f"Severity: {alert.severity}\n"
        f"Asset Name: {alert.asset_name}\n"
        f"IP Address: {alert.ip_address}\n"
        f"Total Downtime: {alert.downtime_duration}\n"
        f"Resolved Time: {alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    
    # Send Dashboard notification
    Notification.objects.create(
        title=subject,
        message=message,
        level='Low'
    )
    
    # Send Webhooks
    config_mgr.load()
    discord_url = config_mgr.get("alerts.discord_webhook_url")
    slack_url = config_mgr.get("alerts.slack_webhook_url")
    teams_url = config_mgr.get("alerts.teams_webhook_url")
    for url in [discord_url, slack_url, teams_url]:
        if url:
            dispatch_notification_via_flask('Webhook', alert.severity, subject, message, webhook_url=url)
            
    # Send Email
    email_key = "level_1_email"
    if alert.severity == "Critical":
        email_key = "level_3_email"
    elif alert.severity == "High":
        email_key = "level_2_email"
    recipient = config_mgr.get(f"alerts.email_recipients.{email_key}")
    if recipient:
        dispatch_notification_via_flask('Email', alert.severity, subject, message, receiver=recipient)

def handle_offline_transition(ip, processed_transitions):
    if ip in processed_transitions:
        return
    processed_transitions.add(ip)
    
    active_alert = AlertEvent.objects.filter(ip_address=ip, status__in=['Active', 'Suppressed']).first()
    now = timezone.now()
    
    asset = Asset.objects.filter(ip_address=ip).first()
    asset_name = asset.asset_name if asset else 'N/A'
    severity = asset.criticality if asset else 'Low'
    
    if active_alert:
        if active_alert.cooldown_expiry and now < active_alert.cooldown_expiry:
            active_alert.occurrence_count += 1
            active_alert.suppression_count += 1
            active_alert.status = 'Suppressed'
            active_alert.last_seen = now
            active_alert.save()
        else:
            active_alert.occurrence_count += 1
            active_alert.status = 'Active'
            active_alert.last_seen = now
            cooldown_mins = config_mgr.get(f"cooldowns.{severity.lower()}", 60)
            active_alert.cooldown_expiry = now + timezone.timedelta(minutes=int(cooldown_mins))
            active_alert.save()
            dispatch_alerts(active_alert)
    else:
        cooldown_mins = config_mgr.get(f"cooldowns.{severity.lower()}", 60)
        new_alert = AlertEvent.objects.create(
            alert_type='Device Offline',
            severity=severity,
            asset_name=asset_name,
            ip_address=ip,
            message=f"Device {ip} ({asset_name if asset else 'Unknown Asset'}) has gone OFFLINE.",
            status='Active',
            created_at=now,
            first_detected=now,
            last_seen=now,
            cooldown_expiry=now + timezone.timedelta(minutes=int(cooldown_mins)),
            alert_source='Scanner'
        )
        dispatch_alerts(new_alert)

def handle_recovery_transition(ip, processed_transitions):
    if ip in processed_transitions:
        return
    processed_transitions.add(ip)
    
    active_alert = AlertEvent.objects.filter(ip_address=ip, status__in=['Active', 'Suppressed']).first()
    if active_alert:
        now = timezone.now()
        active_alert.status = 'Resolved'
        active_alert.resolved_at = now
        active_alert.last_seen = now
        
        # Calculate downtime duration
        downtime = now - active_alert.first_detected
        total_seconds = int(downtime.total_seconds())
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        downtime_str = f"{hours}h {minutes}m {seconds}s" if hours else f"{minutes}m {seconds}s"
        active_alert.downtime_duration = downtime_str
        active_alert.save()
        
        dispatch_recovery(active_alert)

@login_required(login_url='login')
def api_scan_proxy(request):
    """
    Accepts POST {network: '...'}, forwards to Flask scanner on port 5000,
    saves results into the Django Device table under a new ScanSession,
    then returns the JSON.
    Also accepts GET to load the latest ScanSession results from the database.
    """
    if request.method == 'GET':
        devices = []
        last_scan_str = None
        
        # Get the most recent ScanSession
        latest_session = ScanSession.objects.order_by('-timestamp').first()
        if latest_session:
            # Get all devices associated with this scan session
            for dev in latest_session.devices.all():
                devices.append({
                    'ip': dev.ip_address,
                    'mac': dev.mac_address,
                    'role': dev.role,
                    'device_type': dev.device_type,
                    'status': dev.status,
                    'ports': dev.ports,
                    'os': dev.os,
                    'vendor': dev.vendor,
                    'firewall': dev.firewall,
                    'rogue': dev.rogue,
                    'alert': dev.alert,
                    'inactive': dev.inactive,
                    'hostname': dev.hostname,
                })
            last_scan_str = timezone.localtime(latest_session.timestamp).strftime('%d %b %Y, %H:%M:%S')

        return JsonResponse({
            'success': True,
            'last_scan': last_scan_str,
            'devices': devices
        })

    if request.method != 'POST':
        return JsonResponse({'error': 'POST or GET required'}, status=405)

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, Exception):
        return JsonResponse({'error': 'Invalid JSON body'}, status=400)

    network = body.get('network', '').strip()
    if not network:
        return JsonResponse({'error': 'No network provided'}, status=400)

    # ── Forward to Flask ──────────────────────────────────────────────────
    flask_url = 'http://127.0.0.1:5000/scan'
    payload = json.dumps({'network': network}).encode('utf-8')

    try:
        req = urllib.request.Request(
            flask_url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            devices = json.loads(resp.read().decode('utf-8'))
    except urllib.error.URLError as e:
        return JsonResponse({
            'error': f'Flask scanner is not running or unreachable. Start app.py first. ({str(e.reason)})'
        }, status=503)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    # ── Create unique Scan Session ──────────────────────────────────────────
    session = ScanSession.objects.create(network_subnet=network)

    # ── Snapshot pre-scan statuses for transition checks ─────────────────
    db_statuses = {dev.ip_address: dev.status for dev in Device.objects.all()}
    processed_transitions = set()

    # ── Persist results in Django Device table ────────────────────────────
    scanned_ips = {d.get('ip') for d in devices if d.get('ip')}
    import ipaddress
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        net = None
        
    session_devices = []

    if net:
        # If any previously ACTIVE device in the scanned subnet is not detected in the current scan, mark it OFFLINE
        for db_dev in Device.objects.filter(status='ACTIVE'):
            try:
                ip_obj = ipaddress.ip_address(db_dev.ip_address)
                if ip_obj in net and db_dev.ip_address not in scanned_ips:
                    db_dev.status = 'OFFLINE'
                    db_dev.save()
                    handle_offline_transition(db_dev.ip_address, processed_transitions)
                    
                    # Associate with the current scan session
                    session_devices.append(db_dev)
            except ValueError:
                pass

    for d in devices:
        ip = d.get('ip')
        if not ip:
            continue
        new_status = d.get('status', 'ACTIVE')
        
        device_type = _role_to_device_type(d.get('role', ''))
        
        defaults = {
            'ip_address':   ip,
            'mac_address':  d.get('mac', 'Unknown') or 'Unknown',
            'role':         d.get('role', 'Client Device'),
            'device_type':  device_type,
            'status':       new_status,
            'ports':        d.get('ports', []),
            'last_seen':    timezone.now(),
            'os':           d.get('os', 'Unknown') or 'Unknown',
            'vendor':       d.get('vendor', 'Unknown') or 'Unknown',
            'firewall':     d.get('firewall', 'Unknown') or 'Unknown',
            'rogue':        d.get('rogue', 'Normal') or 'Normal',
            'alert':        d.get('alert', 'OK') or 'OK',
            'inactive':     d.get('inactive', '0') or '0',
            'hostname':     d.get('hostname', 'Unknown') or 'Unknown',
        }
        
        # Uniquely identify using MAC Address (preferred) or IP Address (fallback)
        mac = d.get('mac', 'Unknown') or 'Unknown'
        device = None
        clean_mac = mac.strip().lower()
        if clean_mac and clean_mac not in ['unknown', 'unavailable', 'n/a', '']:
            device = Device.objects.filter(mac_address=clean_mac).first()
            
        if not device and ip:
            device = Device.objects.filter(ip_address=ip).first()
            
        if device:
            old_status = device.status
            # Update fields in-place (Do NOT insert another row)
            for k, v in defaults.items():
                setattr(device, k, v)
            device.save()
        else:
            old_status = 'ACTIVE'
            device = Device.objects.create(**defaults)
            
        session_devices.append(device)
        
        # State transition analysis
        if old_status == 'ACTIVE' and new_status == 'OFFLINE':
            handle_offline_transition(ip, processed_transitions)
        elif old_status == 'OFFLINE' and new_status == 'ACTIVE':
            handle_recovery_transition(ip, processed_transitions)

    # Link all these devices to the ScanSession
    session.devices.set(session_devices)

    # Return exactly the devices associated with the latest scan session
    response_devices = []
    for dev in session_devices:
        response_devices.append({
            'ip': dev.ip_address,
            'mac': dev.mac_address,
            'role': dev.role,
            'device_type': dev.device_type,
            'status': dev.status,
            'ports': dev.ports,
            'os': dev.os,
            'vendor': dev.vendor,
            'firewall': dev.firewall,
            'rogue': dev.rogue,
            'alert': dev.alert,
            'inactive': dev.inactive,
            'hostname': dev.hostname,
        })

    return JsonResponse(response_devices, safe=False)


# ─── auth ───────────────────────────────────────────────────────────────────

def login_view(request):
    if request.method == 'POST':
        username_attempt = request.POST.get('username', '').strip()
        
        # Check failed logins limit from config_mgr
        from config_manager import config_mgr
        config_mgr.load()
        failed_limit = config_mgr.get("security.failed_login_limits", 5)
        
        # Count failed logins in the last 15 minutes for this user
        recent_fails = LoginActivity.objects.filter(
            username_attempt=username_attempt,
            event=LoginActivity.EVENT_FAILED_LOGIN,
            timestamp__gte=timezone.now() - timezone.timedelta(minutes=15)
        ).count()
        
        form = AuthenticationForm(request, data=request.POST)
        
        if recent_fails >= failed_limit:
            form.add_error(None, f"This account is temporarily locked due to {recent_fails} failed login attempts. Please try again in 15 minutes.")
        else:
            if form.is_valid():
                user = form.get_user()
                login(request, user)
                LoginActivity.objects.create(
                    user=user,
                    username_attempt=user.username,
                    event=LoginActivity.EVENT_LOGIN,
                    ip_address=_get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:300],
                )
                return redirect('dashboard')
            else:
                # Log failed login attempt
                real_user = User.objects.filter(username=username_attempt).first()
                LoginActivity.objects.create(
                    user=real_user,          # may be None if username doesn't exist
                    username_attempt=username_attempt,
                    event=LoginActivity.EVENT_FAILED_LOGIN,
                    ip_address=_get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:300],
                )
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})


def signup_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            _get_or_create_profile(user)
            LoginActivity.objects.create(
                user=user,
                username_attempt=user.username,
                event=LoginActivity.EVENT_LOGIN,
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:300],
            )
            return redirect('dashboard')
    else:
        form = CustomUserCreationForm()
    return render(request, 'signup.html', {'form': form})


def logout_view(request):
    if request.user.is_authenticated:
        LoginActivity.objects.create(
            user=request.user,
            username_attempt=request.user.username,
            event=LoginActivity.EVENT_LOGOUT,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:300],
        )
    logout(request)
    return redirect('login')


# ─── main pages ─────────────────────────────────────────────────────────────

@login_required(login_url='login')
def landing_view(request):
    return redirect('dashboard')


@login_required(login_url='login')
def api_network_info(request):
    """
    Auto-detects the host's active network adapter IP, netmask, and target CIDR subnet.
    """
    import socket
    import psutil
    import ipaddress

    active_ip = None
    netmask = None
    cidr_subnet = "192.168.1.0/24"  # default fallback

    # 1. Connect a dummy UDP socket to public address to find the active outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        active_ip = s.getsockname()[0]
        s.close()
    except Exception:
        # Fallback to hostname lookup
        try:
            active_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

    # 2. Find matching interface mask using psutil
    if active_ip:
        try:
            for iface, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET and snic.address == active_ip:
                        netmask = snic.netmask
                        break
                if netmask:
                    break
        except Exception:
            pass

    # 3. Calculate subnet network address and CIDR
    if active_ip and netmask:
        try:
            net = ipaddress.IPv4Network(f"{active_ip}/{netmask}", strict=False)
            cidr_subnet = str(net)
        except Exception:
            pass

    return JsonResponse({
        'success': True,
        'active_ip': active_ip or "Unknown",
        'netmask': netmask or "Unknown",
        'cidr_subnet': cidr_subnet
    })


@login_required(login_url='login')
def dashboard_view(request):
    network = request.GET.get('network', '')
    profile = _get_or_create_profile(request.user)
    
    total_assets = Asset.objects.count()
    critical_assets = Asset.objects.filter(criticality='Critical').count()
    high_assets = Asset.objects.filter(criticality='High').count()
    recent_assets = Asset.objects.all()[:3]
    
    return render(request, 'dashboard.html', {
        'username':        request.user.username,
        'network':         network,
        'avatar_url':      profile.get_avatar_url(),
        'total_assets':    total_assets,
        'critical_assets': critical_assets,
        'high_assets':     high_assets,
        'recent_assets':   recent_assets,
    })



# ─── API: granular asset counts ─────────────────────────────────────────────

@login_required(login_url='login')
def api_device_assets(request):
    """
    Returns a JSON object with counts of active devices in each category.
    The dashboard's Network Assets widget polls this endpoint.
    """
    # Auto-correct any existing devices in the database that are marked as 'Unknown'
    unknown_devices = Device.objects.filter(device_type='Unknown')
    for dev in unknown_devices:
        dev.device_type = _role_to_device_type(dev.role)
        dev.save()

    latest_session = ScanSession.objects.order_by('-timestamp').first()
    if latest_session:
        active_devices = latest_session.devices.filter(status='ACTIVE')
    else:
        active_devices = Device.objects.none()

    counts = {
        'pcs':          active_devices.filter(device_type='PC').count(),
        'mobiles':      active_devices.filter(device_type='Mobile').count(),
        'routers':      active_devices.filter(device_type='Router').count(),
        'switches':     active_devices.filter(device_type='Switch').count(),
        'gateways':     active_devices.filter(device_type='Gateway').count(),
        'workstations': active_devices.filter(device_type='Workstation').count(),
        'servers':      active_devices.filter(device_type='Server').count(),
        'databases':    active_devices.filter(device_type='Database').count(),
        'total':        active_devices.count(),
    }
    return JsonResponse(counts)


# ─── Security Logs ───────────────────────────────────────────────────────────

@login_required(login_url='login')
def security_logs_view(request):
    """
    Paginated, searchable audit trail of all login/logout/failed-login events
    across all users (admin view). Regular users see only their own events.
    """
    q = request.GET.get('q', '').strip()
    event_filter = request.GET.get('event', 'ALL')
    page_num = request.GET.get('page', 1)

    logs_qs = LoginActivity.objects.select_related('user').all()

    # Non-superusers only see their own logs
    if not request.user.is_superuser:
        logs_qs = logs_qs.filter(user=request.user)

    # Search filter
    if q:
        logs_qs = logs_qs.filter(
            Q(username_attempt__icontains=q) |
            Q(ip_address__icontains=q) |
            Q(user__username__icontains=q)
        )

    # Event type filter
    if event_filter != 'ALL':
        logs_qs = logs_qs.filter(event=event_filter)

    paginator = Paginator(logs_qs, 25)
    page_obj = paginator.get_page(page_num)

    return render(request, 'security_logs.html', {
        'page_obj':     page_obj,
        'q':            q,
        'event_filter': event_filter,
        'username':     request.user.username,
        'avatar_url':   _get_or_create_profile(request.user).get_avatar_url(),
        'total_count':  logs_qs.count(),
    })


# ─── Edit Profile (split from Settings) ─────────────────────────────────────

@login_required(login_url='login')
def edit_profile_view(request):
    profile = _get_or_create_profile(request.user)
    pw_form = PasswordChangeForm(request.user)
    success = None
    error = None

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'profile':
            new_username = request.POST.get('username', '').strip()
            new_email    = request.POST.get('email', '').strip()
            new_bio      = request.POST.get('bio', '').strip()
            new_dept     = request.POST.get('department', '').strip()

            if new_username and new_username != request.user.username:
                if User.objects.filter(username=new_username).exclude(pk=request.user.pk).exists():
                    error = 'Username already taken.'
                else:
                    request.user.username = new_username
                    request.user.save()

            if new_email:
                profile.email = new_email
            profile.bio = new_bio
            profile.department = new_dept

            # Clear avatar
            if request.POST.get('clear_avatar') == '1' and not request.FILES.get('avatar'):
                if profile.avatar:
                    old_path = profile.avatar.path
                    profile.avatar = None
                    if os.path.isfile(old_path):
                        os.remove(old_path)

            # Upload new avatar
            elif 'avatar' in request.FILES:
                if profile.avatar:
                    old_path = profile.avatar.path
                    if os.path.isfile(old_path):
                        os.remove(old_path)
                profile.avatar = request.FILES['avatar']

            profile.save()
            if not error:
                success = 'Profile updated successfully!'

        elif action == 'password':
            pw_form = PasswordChangeForm(request.user, request.POST)
            if pw_form.is_valid():
                user = pw_form.save()
                update_session_auth_hash(request, user)
                success = 'Password changed successfully!'
            else:
                error = 'Password change failed. Check the fields below.'

    return render(request, 'edit_profile.html', {
        'username':   request.user.username,
        'profile':    profile,
        'avatar_url': profile.get_avatar_url(),
        'pw_form':    pw_form,
        'success':    success,
        'error':      error,
    })


# ─── Settings — IT Contacts + Global Config ─────────────────────────────────

@login_required(login_url='login')
def settings_view(request):
    profile      = _get_or_create_profile(request.user)
    global_cfg   = GlobalSettings.get_instance()
    is_admin     = request.user.is_superuser or request.user.is_staff

    contact_form    = ITContactForm()
    gs_form         = GlobalSettingsForm(instance=global_cfg)
    edit_contact    = None
    success_msg     = None
    error_msg       = None

    if request.method == 'POST':
        if not is_admin:
            error_msg = 'Permission denied — admin access required.'
        else:
            action = request.POST.get('action', '')

            # ── Add new contact ──────────────────────────────────────────
            if action == 'add_contact':
                contact_form = ITContactForm(request.POST)
                if contact_form.is_valid():
                    contact_form.save()
                    success_msg  = 'Contact added successfully.'
                    contact_form = ITContactForm()      # reset
                else:
                    error_msg = 'Please fix the errors below.'

            # ── Edit/update an existing contact ──────────────────────────
            elif action == 'edit_contact':
                contact_id = request.POST.get('contact_id')
                try:
                    obj = ITContact.objects.get(pk=contact_id)
                    f   = ITContactForm(request.POST, instance=obj)
                    if f.is_valid():
                        f.save()
                        success_msg = f'Contact "{obj.name}" updated.'
                    else:
                        error_msg = 'Please fix the form errors.'
                        contact_form = f
                except ITContact.DoesNotExist:
                    error_msg = 'Contact not found.'

            # ── Delete a contact ─────────────────────────────────────────
            elif action == 'delete_contact':
                contact_id = request.POST.get('contact_id')
                try:
                    obj = ITContact.objects.get(pk=contact_id)
                    name = obj.name
                    obj.delete()
                    success_msg = f'Contact "{name}" deleted.'
                except ITContact.DoesNotExist:
                    error_msg = 'Contact not found.'

            # ── Save global settings (IP range + scan interval) ───────────
            elif action == 'save_global':
                gs_form = GlobalSettingsForm(request.POST, instance=global_cfg)
                if gs_form.is_valid():
                    gs_form.save()
                    global_cfg  = GlobalSettings.get_instance()   # refresh
                    gs_form     = GlobalSettingsForm(instance=global_cfg)
                    success_msg = 'Global settings saved.'
                else:
                    error_msg = 'Invalid settings — check the form fields.'

    # Pre-populate edit form if ?edit=<id> in the GET params
    edit_id = request.GET.get('edit')
    if edit_id and is_admin:
        try:
            edit_contact = ITContact.objects.get(pk=edit_id)
            contact_form = ITContactForm(instance=edit_contact)
        except ITContact.DoesNotExist:
            pass

    contacts = ITContact.objects.all()

    return render(request, 'settings.html', {
        'username':      request.user.username,
        'avatar_url':    profile.get_avatar_url(),
        'is_admin':      is_admin,
        'contacts':      contacts,
        'contact_form':  contact_form,
        'edit_contact':  edit_contact,
        'gs_form':       gs_form,
        'global_cfg':    global_cfg,
        'success_msg':   success_msg,
        'error_msg':     error_msg,
    })


# ─── Account / Profile overview ─────────────────────────────────────────────

@login_required(login_url='login')
def account_view(request):
    profile = _get_or_create_profile(request.user)

    total_logins = LoginActivity.objects.filter(
        user=request.user, event=LoginActivity.EVENT_LOGIN
    ).count()
    last_login_obj = LoginActivity.objects.filter(
        user=request.user, event=LoginActivity.EVENT_LOGIN
    ).first()

    return render(request, 'account.html', {
        'username':      request.user.username,
        'profile':       profile,
        'avatar_url':    profile.get_avatar_url(),
        'total_logins':  total_logins,
        'last_login_obj': last_login_obj,
        'member_since':  request.user.date_joined,
    })


# ─── Network Map ─────────────────────────────────────────────────────────────

@login_required(login_url='login')
def network_map_view(request):
    """
    Groups ALL scanned devices (ACTIVE + OFFLINE) into subnet zones derived
    automatically from each device's actual /24 prefix. Devices in known
    named subnets (SUBNET_ZONES) keep their label; everything else gets a
    CIDR label like '10.233.189.0/24'. A distinct colour is generated per
    unique prefix so no two subnets share the same colour.
    """
    import ipaddress as _ipa

    profile = _get_or_create_profile(request.user)

    latest_session = ScanSession.objects.order_by('-timestamp').first()
    if latest_session:
        devices = latest_session.devices.all()
    else:
        devices = Device.objects.none()

    # Deterministic colour palette — picked to look good on the dark background
    SUBNET_PALETTE = [
        '#33cc66',  # green  — SOC
        '#3b82f6',  # blue   — Admin
        '#f59e0b',  # amber  — Corporate
        '#ef4444',  # red    — DMZ
        '#06b6d4',  # cyan
        '#a78bfa',  # violet
        '#fb923c',  # orange
        '#e879f9',  # fuchsia
        '#34d399',  # emerald
        '#60a5fa',  # light-blue
        '#fbbf24',  # yellow
        '#f472b6',  # pink
    ]

    # Build prefix → zone dict, merging known names with auto-detected ones
    zones: dict[str, dict] = {}
    palette_idx = 0

    for device in devices:
        ip = device.ip_address
        try:
            # /24 subnet prefix as a string key, e.g. "10.233.189"
            parts = ip.split('.')
            prefix = '.'.join(parts[:3])
            cidr_label = f'{parts[0]}.{parts[1]}.{parts[2]}.0/24'
        except Exception:
            prefix = 'unknown'
            cidr_label = 'Unknown'

        if prefix not in zones:
            # Try the hardcoded named zones first
            if prefix in SUBNET_ZONES:
                zone_name  = SUBNET_ZONES[prefix]['name']
                zone_color = SUBNET_ZONES[prefix]['color']
            else:
                zone_name  = cidr_label          # e.g. "10.233.189.0/24"
                zone_color = SUBNET_PALETTE[palette_idx % len(SUBNET_PALETTE)]
                palette_idx += 1

            zones[prefix] = {
                'name':    zone_name,
                'color':   zone_color,
                'devices': [],
            }

        zones[prefix]['devices'].append({
            'id':          device.pk,
            'ip':          device.ip_address,
            'mac':         device.mac_address,
            'role':        device.role,
            'device_type': device.device_type,
            'status':      device.status,   # 'ACTIVE' | 'OFFLINE'
        })

    zones_json = json.dumps(list(zones.values()))

    return render(request, 'network_map.html', {
        'username':   request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'zones_json': zones_json,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── Asset Management Module Views ──
# ══════════════════════════════════════════════════════════════════════════════

import csv
from datetime import date, timedelta
from django.http import HttpResponse
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404


@login_required(login_url='login')
def asset_list_view(request):
    profile = _get_or_create_profile(request.user)
    
    # Filter inputs
    q = request.GET.get('q', '').strip()
    criticality = request.GET.get('criticality', '').strip()
    asset_type = request.GET.get('asset_type', '').strip()
    status = request.GET.get('status', '').strip()
    location = request.GET.get('location', '').strip()
    sort_by = request.GET.get('sort', '-created_at').strip()
    
    assets = Asset.objects.all()
    
    if q:
        assets = assets.filter(
            Q(asset_name__icontains=q) | 
            Q(description__icontains=q) | 
            Q(owner_name__icontains=q) | 
            Q(ip_address__icontains=q)
        )
    if criticality:
        assets = assets.filter(criticality=criticality)
    if asset_type:
        assets = assets.filter(asset_type__iexact=asset_type)
    if status:
        assets = assets.filter(status=status)
    if location:
        assets = assets.filter(location__icontains=location)
        
    # Sort validation
    valid_sorts = ['asset_name', '-asset_name', 'criticality', '-criticality', 'created_at', '-created_at', 'owner_name', '-owner_name']
    if sort_by not in valid_sorts:
        sort_by = '-created_at'
    assets = assets.order_by(sort_by)
    
    # Unique types, locations, and owners for dropdown filters
    all_types = Asset.objects.values_list('asset_type', flat=True).distinct().order_by('asset_type')
    all_locations = Asset.objects.values_list('location', flat=True).distinct().order_by('location')
    
    # Pagination
    paginator = Paginator(assets, 15)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)
    
    is_admin = request.user.is_superuser or request.user.is_staff
    
    return render(request, 'asset_list.html', {
        'username': request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'page_obj': page_obj,
        'q': q,
        'criticality_filter': criticality,
        'type_filter': asset_type,
        'status_filter': status,
        'location_filter': location,
        'sort_by': sort_by,
        'all_types': all_types,
        'all_locations': all_locations,
        'is_admin': is_admin,
    })


@login_required(login_url='login')
def asset_detail_view(request, pk):
    profile = _get_or_create_profile(request.user)
    asset = get_object_or_404(Asset, pk=pk)
    is_admin = request.user.is_superuser or request.user.is_staff
    is_creator = asset.added_by == request.user
    
    return render(request, 'asset_detail.html', {
        'username': request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'asset': asset,
        'importance_score': asset.get_importance_score(),
        'potential_impact': asset.get_potential_impact(),
        'is_admin': is_admin,
        'can_edit': is_admin or is_creator,
    })


@login_required(login_url='login')
def asset_create_view(request):
    profile = _get_or_create_profile(request.user)
    
    if request.method == 'POST':
        form = AssetForm(request.POST)
        if form.is_valid():
            asset = form.save(commit=False)
            asset.added_by = request.user
            asset.save()
            
            # Generate Notifications
            Notification.objects.create(
                title="New Asset Added",
                message=f"Asset '{asset.asset_name}' of type '{asset.asset_type}' was successfully registered by {request.user.username}.",
                level="Low"
            )
            if asset.criticality == 'Critical':
                Notification.objects.create(
                    title="Critical Asset Added",
                    message=f"ALERT: A new Critical Asset '{asset.asset_name}' has been added by {request.user.username}!",
                    level="Critical"
                )
            
            messages.success(request, f"Asset '{asset.asset_name}' added successfully.")
            return redirect('asset_list')
    else:
        # Prepopulate ownership info from logged-in user profile details
        full_name = f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username
        initial_data = {
            'owner_name': full_name,
            'owner_email': request.user.email,
        }
        form = AssetForm(initial=initial_data)
        
    return render(request, 'asset_form.html', {
        'username': request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'form': form,
        'is_edit': False,
    })


@login_required(login_url='login')
def asset_edit_view(request, pk):
    profile = _get_or_create_profile(request.user)
    asset = get_object_or_404(Asset, pk=pk)
    
    is_admin = request.user.is_superuser or request.user.is_staff
    if not (is_admin or asset.added_by == request.user):
        raise PermissionDenied("You do not have permission to edit this asset.")
        
    if request.method == 'POST':
        form = AssetForm(request.POST, instance=asset)
        if form.is_valid():
            updated_asset = form.save()
            
            Notification.objects.create(
                title="Asset Updated",
                message=f"Asset '{updated_asset.asset_name}' was updated by {request.user.username}.",
                level="Medium" if updated_asset.criticality in ['High', 'Critical'] else "Low"
            )
            
            messages.success(request, f"Asset '{updated_asset.asset_name}' updated successfully.")
            return redirect('asset_detail', pk=updated_asset.pk)
    else:
        form = AssetForm(instance=asset)
        
    return render(request, 'asset_form.html', {
        'username': request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'form': form,
        'is_edit': True,
        'asset': asset,
    })


@login_required(login_url='login')
def asset_delete_view(request, pk):
    asset = get_object_or_404(Asset, pk=pk)
    
    is_admin = request.user.is_superuser or request.user.is_staff
    if not is_admin:
        raise PermissionDenied("Only administrators can delete assets.")
        
    if request.method == 'POST':
        asset_name = asset.asset_name
        asset.delete()
        
        Notification.objects.create(
            title="Asset Deleted",
            message=f"Asset '{asset_name}' was permanently deleted by admin {request.user.username}.",
            level="High"
        )
        
        messages.success(request, f"Asset '{asset_name}' was deleted.")
        return redirect('asset_list')
        
    return redirect('asset_detail', pk=pk)


@login_required(login_url='login')
def asset_export_view(request):
    q = request.GET.get('q', '').strip()
    criticality = request.GET.get('criticality', '').strip()
    asset_type = request.GET.get('asset_type', '').strip()
    status = request.GET.get('status', '').strip()
    location = request.GET.get('location', '').strip()
    
    assets = Asset.objects.all()
    if q:
        assets = assets.filter(
            Q(asset_name__icontains=q) | 
            Q(description__icontains=q) | 
            Q(owner_name__icontains=q)
        )
    if criticality:
        assets = assets.filter(criticality=criticality)
    if asset_type:
        assets = assets.filter(asset_type__iexact=asset_type)
    if status:
        assets = assets.filter(status=status)
    if location:
        assets = assets.filter(location__icontains=location)
        
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="cyber_assets.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Asset Name', 'Asset Type', 'Description', 'Owner Name', 'Owner Email', 'Owner Contact',
        'Department', 'Location', 'Business Unit', 'Criticality', 'IP Address', 'MAC Address',
        'Operating System', 'Vendor', 'Model', 'Serial Number', 'Purchase Date', 'Warranty Expiry',
        'Status', 'Notes', 'Added By', 'Created At'
    ])
    
    for a in assets:
        writer.writerow([
            a.asset_name, a.asset_type, a.description, a.owner_name, a.owner_email, a.owner_contact,
            a.department, a.location, a.business_unit, a.criticality, a.ip_address or '', a.mac_address or '',
            a.operating_system or '', a.vendor or '', a.model or '', a.serial_number or '',
            a.purchase_date or '', a.warranty_expiry or '', a.status, a.notes, a.added_by.username, a.created_at
        ])
    return response


@login_required(login_url='login')
def api_notifications(request):
    upcoming_limit = date.today() + timedelta(days=30)
    expiring_assets = Asset.objects.filter(
        warranty_expiry__lte=upcoming_limit,
        warranty_expiry__gte=date.today()
    )
    for asset in expiring_assets:
        title = "Warranty Expiring Soon"
        message = f"Warranty for asset '{asset.asset_name}' is expiring on {asset.warranty_expiry}."
        Notification.objects.get_or_create(
            title=title,
            message=message,
            defaults={'level': 'Medium', 'type': 'Warranty'}
        )
        
    notifs = Notification.objects.all()[:15]
    notifs_data = [{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'level': n.level,
        'type': n.type,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': n.is_read,
        'read_at': n.read_at.strftime('%Y-%m-%d %H:%M:%S') if n.read_at else None
    } for n in notifs]
    
    return JsonResponse({'success': True, 'notifications': notifs_data})


@csrf_exempt
@login_required(login_url='login')
def api_mark_notifications_read(request):
    if request.method == 'POST':
        Notification.objects.filter(is_read=False).update(
            is_read=True,
            read_at=timezone.now()
        )
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'POST required'}, status=405)


@login_required(login_url='login')
def config_view(request):
    if not (request.user.is_superuser or request.user.is_staff):
        messages.error(request, "Access denied: Only Administrator users can access Configuration settings.")
        return redirect('dashboard')
    
    from config_manager import config_mgr
    config_mgr.load()
    
    profile = _get_or_create_profile(request.user)
    
    return render(request, 'config.html', {
        'username': request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'config': config_mgr.config,
    })


@csrf_exempt
@login_required(login_url='login')
def api_config_endpoint(request):
    if not (request.user.is_superuser or request.user.is_staff):
        return JsonResponse({"error": "Admin access required"}, status=403)
        
    from config_manager import config_mgr
    config_mgr.load()
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            # Validate proposed data
            errors = config_mgr.validate(data)
            if errors:
                return JsonResponse({"success": False, "errors": errors}, status=400)
            
            # Save configuration options
            for section_key, section_val in data.items():
                if isinstance(section_val, dict):
                    for k, v in section_val.items():
                        if isinstance(v, dict):
                            for sub_k, sub_v in v.items():
                                config_mgr.set(f"{section_key}.{k}.{sub_k}", sub_v)
                        else:
                            config_mgr.set(f"{section_key}.{k}", v)
                else:
                    config_mgr.set(section_key, section_val)
            
            config_mgr.save()
            
            # Sync to global settings database table
            try:
                from .models import GlobalSettings
                global_cfg = GlobalSettings.get_instance()
                global_cfg.default_ip_range = config_mgr.get("network.default_ip_range")
                global_cfg.scan_interval = str(config_mgr.get("network.scan_interval"))
                global_cfg.level_1_email = config_mgr.get("alerts.email_recipients.level_1_email")
                global_cfg.level_2_email = config_mgr.get("alerts.email_recipients.level_2_email")
                global_cfg.level_3_email = config_mgr.get("alerts.email_recipients.level_3_email")
                global_cfg.save()
            except Exception as e:
                print(f"Error syncing config to Django DB: {e}")
                
            return JsonResponse({"success": True})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
            
    # GET configuration
    return JsonResponse(config_mgr.config)


@login_required(login_url='login')
def api_config_export(request):
    if not (request.user.is_superuser or request.user.is_staff):
        return JsonResponse({"error": "Admin access required"}, status=403)
        
    from config_manager import config_mgr
    config_mgr.load()
    
    response = HttpResponse(config_mgr.export_config(), content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="config.json"'
    return response


@csrf_exempt
@login_required(login_url='login')
def api_config_restore(request):
    if not (request.user.is_superuser or request.user.is_staff):
        return JsonResponse({"error": "Admin access required"}, status=403)
        
    from config_manager import config_mgr
    config_mgr.restore_defaults()
    
    # Sync database
    try:
        from .models import GlobalSettings
        global_cfg = GlobalSettings.get_instance()
        global_cfg.default_ip_range = config_mgr.get("network.default_ip_range")
        global_cfg.scan_interval = str(config_mgr.get("network.scan_interval"))
        global_cfg.level_1_email = config_mgr.get("alerts.email_recipients.level_1_email")
        global_cfg.level_2_email = config_mgr.get("alerts.email_recipients.level_2_email")
        global_cfg.level_3_email = config_mgr.get("alerts.email_recipients.level_3_email")
        global_cfg.save()
    except Exception as e:
        print(f"Error syncing config to Django DB: {e}")
        
    return JsonResponse({"success": True})


# ─── ALERT HISTORY VIEW ──────────────────────────────────────────────────
@login_required(login_url='login')
def alerts_history_view(request):
    profile = _get_or_create_profile(request.user)
    queryset = AlertEvent.objects.all()
    q = request.GET.get('q', '').strip()
    if q:
        queryset = queryset.filter(
            Q(ip_address__icontains=q) | Q(message__icontains=q) |
            Q(asset_name__icontains=q) | Q(alert_type__icontains=q)
        )
    status = request.GET.get('status', '').strip()
    if status:
        queryset = queryset.filter(status=status)
    severity = request.GET.get('severity', '').strip()
    if severity:
        queryset = queryset.filter(severity=severity)
    source = request.GET.get('source', '').strip()
    if source:
        queryset = queryset.filter(alert_source=source)
    sort_by = request.GET.get('sort_by', '-created_at').strip()
    valid_sort_fields = {
        'created_at': 'created_at', '-created_at': '-created_at',
        'severity': 'severity', '-severity': '-severity',
        'status': 'status', '-status': '-status',
        'ip_address': 'ip_address', '-ip_address': '-ip_address',
        'occurrence_count': 'occurrence_count', '-occurrence_count': '-occurrence_count',
        'downtime': 'downtime_duration', '-downtime': '-downtime_duration'
    }
    db_sort = valid_sort_fields.get(sort_by, '-created_at')
    if db_sort in ['severity', '-severity']:
        from django.db.models import Case, When, Value, IntegerField
        queryset = queryset.annotate(
            severity_weight=Case(
                When(severity='Critical', then=Value(4)),
                When(severity='High', then=Value(3)),
                When(severity='Medium', then=Value(2)),
                When(severity='Low', then=Value(1)),
                default=Value(0), output_field=IntegerField(),
            )
        )
        queryset = queryset.order_by('-severity_weight' if db_sort == '-severity' else 'severity_weight', '-created_at')
    else:
        queryset = queryset.order_by(db_sort)
    paginator = Paginator(queryset, 15)
    page_obj = paginator.get_page(request.GET.get('page'))
    total_count = AlertEvent.objects.count()
    active_count = AlertEvent.objects.filter(status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()
    resolved_count = AlertEvent.objects.filter(status__in=['Resolved', 'Closed']).count()
    suppressed_count = AlertEvent.objects.filter(status='Suppressed').count()
    return render(request, 'alerts_history.html', {
        'username': request.user.username, 'avatar_url': profile.get_avatar_url(),
        'page_obj': page_obj, 'total_count': total_count, 'active_count': active_count,
        'resolved_count': resolved_count, 'suppressed_count': suppressed_count,
        'current_q': q, 'current_status': status, 'current_severity': severity,
        'current_source': source, 'current_sort_by': sort_by,
    })


@login_required(login_url='login')
def api_resolve_alert(request, pk):
    alert = get_object_or_404(AlertEvent, pk=pk)
    if alert.status in ['New', 'Active', 'Acknowledged', 'Investigating']:
        alert.status = 'Resolved'
        alert.resolved_at = timezone.now()
        alert.save()
        messages.success(request, f"Alert #{alert.id} resolved successfully.")
    else:
        messages.info(request, f"Alert #{alert.id} is already resolved.")
    return redirect('alerts_history')


# ─── API ALERT METRICS ────────────────────────────────────────────────────────
@login_required(login_url='login')
def api_alert_metrics(request):
    active_count = AlertEvent.objects.filter(status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()
    resolved_count = AlertEvent.objects.filter(status__in=['Resolved', 'Closed']).count()
    suppressed_count = AlertEvent.objects.filter(status='Suppressed').count()
    total_count = AlertEvent.objects.count()
    resolved_alerts = AlertEvent.objects.filter(status__in=['Resolved', 'Closed'], resolved_at__isnull=False)
    avg_minutes = 0.0
    if resolved_alerts.exists():
        total_minutes = 0
        count = 0
        for alert in resolved_alerts:
            if alert.resolved_at and alert.first_detected:
                dur = alert.resolved_at - alert.first_detected
                total_minutes += int(dur.total_seconds() / 60)
                count += 1
        if count > 0:
            avg_minutes = round(total_minutes / count, 1)
    return JsonResponse({
        'active': active_count, 'resolved': resolved_count,
        'suppressed': suppressed_count, 'total': total_count,
        'avg_resolution_time_min': avg_minutes
    })

@login_required(login_url='login')
def alerts_export_csv(request):
    import csv
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="alerts_history.csv"'
    writer = csv.writer(response)
    writer.writerow([
        'Alert ID', 'Alert Type', 'Severity', 'Asset Name', 'IP Address',
        'Message', 'Status', 'Created Time', 'Resolved Time',
        'Downtime Duration', 'Alert Source', 'Occurrence Count', 'Suppression Count'
    ])
    for a in AlertEvent.objects.all().order_by('-created_at'):
        writer.writerow([
            a.id, a.alert_type, a.severity, a.asset_name, a.ip_address or 'N/A',
            a.message, a.status, a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            a.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if a.resolved_at else 'N/A',
            a.downtime_duration or 'N/A', a.alert_source, a.occurrence_count, a.suppression_count
        ])
    return response


@login_required(login_url='login')
def alerts_export_pdf(request):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        REPORTLAB_AVAILABLE = True
    except ImportError:
        REPORTLAB_AVAILABLE = False
    if not REPORTLAB_AVAILABLE:
        alerts = AlertEvent.objects.all().order_by('-created_at')
        html_content = """<html><head><title>Alerts History Report</title>
        <style>body{font-family:Arial,sans-serif;background:#fff;color:#000;padding:20px}
        h1{color:#c00}table{width:100%;border-collapse:collapse;margin-top:20px}
        th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:12px}
        th{background-color:#f2f2f2}tr:nth-child(even){background-color:#f9f9f9}
        </style></head><body onload="window.print()">
        <h1>Monitor OS — Alert History Report</h1>
        <p>Generated on: """ + timezone.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        <table><thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Asset Name</th>
        <th>IP Address</th><th>Message</th><th>Status</th><th>Created At</th>
        <th>Downtime</th></tr></thead><tbody>"""
        for a in alerts:
            html_content += f"<tr><td>{a.id}</td><td>{a.alert_type}</td><td>{a.severity}</td><td>{a.asset_name}</td><td>{a.ip_address or 'N/A'}</td><td>{a.message}</td><td>{a.status}</td><td>{a.created_at.strftime('%Y-%m-%d %H:%M:%S')}</td><td>{a.downtime_duration or 'N/A'}</td></tr>"
        html_content += "</tbody></table></body></html>"
        return HttpResponse(html_content, content_type='text/html')
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="alerts_history.pdf"'
    doc = SimpleDocTemplate(response, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name='TitleStyle', parent=styles['Heading1'], fontSize=20,
        textColor=colors.HexColor('#ef4444'), spaceAfter=20)
    story.append(Paragraph("Monitor OS — Alert History Report", title_style))
    story.append(Paragraph(f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 15))
    data = [[Paragraph(f"<b>{h}</b>", styles['Normal']) for h in ['ID','Type','Severity','IP Address','Message','Status','Created At']]]
    for a in AlertEvent.objects.all().order_by('-created_at')[:100]:
        data.append([Paragraph(str(x), styles['Normal']) for x in [
            a.id, a.alert_type, a.severity, a.ip_address or 'N/A', a.message, a.status,
            a.created_at.strftime('%Y-%m-%d %H:%M:%S')]])
    table = Table(data, colWidths=[30, 70, 60, 90, 150, 60, 90])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f2f2f2')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'), ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
    ]))
    story.append(table)
    doc.build(story)
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# INCIDENT RESPONSE CENTER VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

@login_required(login_url='login')
def incident_response_view(request):
    """Main SOC Incident Response table with search, filter, sort, pagination."""
    profile = _get_or_create_profile(request.user)
    queryset = Incident.objects.select_related('assigned_to', 'alert_event').all()

    # Search
    q = request.GET.get('q', '').strip()
    if q:
        queryset = queryset.filter(
            Q(incident_id__icontains=q) |
            Q(title__icontains=q) |
            Q(asset_name__icontains=q) |
            Q(ip_address__icontains=q)
        )

    # Filters
    status_filter   = request.GET.get('status', '').strip()
    severity_filter = request.GET.get('severity', '').strip()
    sla_filter      = request.GET.get('sla', '').strip()

    if status_filter:
        queryset = queryset.filter(status=status_filter)
    if severity_filter:
        queryset = queryset.filter(severity=severity_filter)

    # Sorting
    sort_by = request.GET.get('sort_by', '-created_at').strip()
    valid_sorts = {
        'created_at': 'created_at', '-created_at': '-created_at',
        'severity': 'severity', '-severity': '-severity',
        'status': 'status', '-status': '-status',
        'started_at': 'started_at', '-started_at': '-started_at',
    }
    queryset = queryset.order_by(valid_sorts.get(sort_by, '-created_at'))

    # Post-filter for SLA (computed property — must filter in Python)
    if sla_filter in ('Met', 'Breached', 'Pending'):
        queryset = [inc for inc in queryset if inc.sla_status == sla_filter]
    else:
        queryset = list(queryset)

    # Paginate
    paginator = Paginator(queryset, 15)
    page_obj  = paginator.get_page(request.GET.get('page'))

    # Metrics
    all_incidents = Incident.objects.all()
    active_count   = all_incidents.filter(status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()
    resolved_list  = [i for i in all_incidents if i.resolution_time_minutes is not None]
    mttr           = round(sum(i.resolution_time_minutes for i in resolved_list) / len(resolved_list), 1) if resolved_list else 0
    sla_met        = sum(1 for i in resolved_list if i.sla_status == 'Met')
    sla_breached   = sum(1 for i in resolved_list if i.sla_status == 'Breached')
    sla_pct        = round(sla_met / len(resolved_list) * 100, 1) if resolved_list else 100
    critical_open  = all_incidents.filter(severity='Critical', status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()

    users = User.objects.all()

    return render(request, 'incident_response.html', {
        'username':       request.user.username,
        'avatar_url':     profile.get_avatar_url(),
        'page_obj':       page_obj,
        'current_q':      q,
        'current_status': status_filter,
        'current_severity': severity_filter,
        'current_sla':    sla_filter,
        'current_sort_by': sort_by,
        # Metrics
        'active_count':   active_count,
        'resolved_count': len(resolved_list),
        'mttr':           mttr,
        'sla_pct':        sla_pct,
        'sla_breached':   sla_breached,
        'critical_open':  critical_open,
        'total_count':    all_incidents.count(),
        # Form data
        'users': users,
        'alert_events': AlertEvent.objects.filter(status__in=['New', 'Active', 'Acknowledged', 'Investigating']).order_by('-created_at')[:50],
    })


@login_required(login_url='login')
def incident_create_view(request):
    """Create a new incident (POST only). Redirects to incident_response on success."""
    if request.method == 'POST':
        title       = request.POST.get('title', '').strip()
        asset_name  = request.POST.get('asset_name', 'N/A').strip()
        ip_address  = request.POST.get('ip_address', '').strip() or None
        severity    = request.POST.get('severity', 'Medium')
        status      = request.POST.get('status', 'New')
        notes       = request.POST.get('notes', '').strip()
        assigned_id = request.POST.get('assigned_to', '')
        alert_id    = request.POST.get('alert_event_id', '')
        due_date_raw = request.POST.get('due_date', '')

        assigned_user = None
        if assigned_id:
            try:
                assigned_user = User.objects.get(pk=int(assigned_id))
            except (User.DoesNotExist, ValueError):
                pass

        alert_event = None
        if alert_id:
            try:
                alert_event = AlertEvent.objects.get(pk=int(alert_id))
                if not asset_name or asset_name == 'N/A':
                    asset_name = alert_event.asset_name
                if not ip_address:
                    ip_address = str(alert_event.ip_address) if alert_event.ip_address else None
            except (AlertEvent.DoesNotExist, ValueError):
                pass

        due_date = None
        if due_date_raw:
            from django.utils.dateparse import parse_datetime
            due_date = parse_datetime(due_date_raw)

        if not title:
            messages.error(request, 'Incident title is required.')
            return redirect('incident_response')

        history_entry = []
        if assigned_user:
            history_entry = [{
                'time': timezone.now().isoformat(),
                'assigned_to': assigned_user.username,
                'assigned_by': request.user.username
            }]

        inc = Incident.objects.create(
            title=title,
            asset_name=asset_name or 'N/A',
            ip_address=ip_address,
            severity=severity,
            status=status,
            notes=notes,
            assigned_to=assigned_user,
            alert_event=alert_event,
            source='Manual',
            due_date=due_date,
            assignment_history=history_entry,
        )
        messages.success(request, f'Incident {inc.incident_id} created successfully.')
        return redirect('incident_response')

    return redirect('incident_response')


@login_required(login_url='login')
def incident_detail_view(request, pk):
    """Detail / timeline view for a single incident."""
    profile = _get_or_create_profile(request.user)
    try:
        incident = Incident.objects.select_related('assigned_to', 'alert_event').prefetch_related('comments__user', 'evidences__uploaded_by').get(pk=pk)
    except Incident.DoesNotExist:
        messages.error(request, 'Incident not found.')
        return redirect('incident_response')

    users = User.objects.all()
    comments = incident.comments.all().order_by('timestamp')
    evidences = incident.evidences.all().order_by('uploaded_at')

    return render(request, 'incident_detail.html', {
        'username':   request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'incident':   incident,
        'users':      users,
        'timeline':   incident.timeline_events,
        'comments':   comments,
        'evidences':  evidences,
    })


@login_required(login_url='login')
def incident_update_status_view(request):
    """AJAX endpoint to update incident status / acknowledgement / resolution."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)

    try:
        data    = json.loads(request.body)
        inc_id  = data.get('incident_id')
        new_status = data.get('status', '').strip()
        inc = Incident.objects.get(pk=inc_id)

        inc.status = new_status
        now = timezone.now()

        if new_status == 'Acknowledged' and not inc.acknowledged_at:
            inc.acknowledged_at = now
        if new_status in ('Resolved', 'Closed') and not inc.resolved_at:
            inc.resolved_at = now
        if new_status == 'Closed' and not inc.closed_at:
            inc.closed_at = now

        # Optional: update notes, assigned_to, due_date
        if 'notes' in data:
            inc.notes = data['notes']
            
        if 'due_date' in data:
            if data['due_date']:
                from django.utils.dateparse import parse_datetime
                inc.due_date = parse_datetime(data['due_date'])
            else:
                inc.due_date = None

        if 'assigned_to_id' in data:
            try:
                new_user_id = data['assigned_to_id']
                if new_user_id:
                    new_user = User.objects.get(pk=int(new_user_id))
                    if not inc.assigned_to or inc.assigned_to.pk != new_user.pk:
                        history_entry = {
                            'time': now.isoformat(),
                            'assigned_to': new_user.username,
                            'assigned_by': request.user.username
                        }
                        if not isinstance(inc.assignment_history, list):
                            inc.assignment_history = []
                        inc.assignment_history.append(history_entry)
                        inc.assigned_to = new_user
                else:
                    if inc.assigned_to:
                        history_entry = {
                            'time': now.isoformat(),
                            'assigned_to': 'Unassigned',
                            'assigned_by': request.user.username
                        }
                        if not isinstance(inc.assignment_history, list):
                            inc.assignment_history = []
                        inc.assignment_history.append(history_entry)
                        inc.assigned_to = None
            except (User.DoesNotExist, ValueError):
                pass

        inc.save()
        return JsonResponse({
            'success': True,
            'incident_id': inc.incident_id,
            'status': inc.status,
            'sla_status': inc.sla_status,
            'response_time': inc.response_time_minutes,
            'resolution_time': inc.resolution_time_minutes,
        })
    except Incident.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Incident not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required(login_url='login')
def api_incident_metrics(request):
    """JSON metrics for dashboard Incident Summary widget."""
    all_inc = Incident.objects.all()
    active  = all_inc.filter(status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()
    resolved_list = [i for i in all_inc if i.resolution_time_minutes is not None]
    mttr    = round(sum(i.resolution_time_minutes for i in resolved_list) / len(resolved_list), 1) if resolved_list else 0
    sla_met = sum(1 for i in resolved_list if i.sla_status == 'Met')
    sla_pct = round(sla_met / len(resolved_list) * 100, 1) if resolved_list else 100
    sla_breached = sum(1 for i in resolved_list if i.sla_status == 'Breached')
    critical_open = all_inc.filter(severity='Critical', status__in=['New', 'Active', 'Acknowledged', 'Investigating']).count()
    return JsonResponse({
        'active':         active,
        'resolved':       len(resolved_list),
        'total':          all_inc.count(),
        'mttr_min':       mttr,
        'sla_pct':        sla_pct,
        'sla_breached':   sla_breached,
        'critical_open':  critical_open,
    })


@login_required(login_url='login')
def api_incident_export_csv(request):
    """Export all incidents as CSV."""
    import csv
    from django.http import HttpResponse as HR
    response = HR(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="incidents.csv"'
    writer = csv.writer(response)
    writer.writerow([
        'Incident ID', 'Title', 'Asset Name', 'IP Address', 'Severity', 'Status',
        'Assigned To', 'Started At', 'Acknowledged At', 'Resolved At',
        'Response Time (min)', 'Resolution Time (min)', 'SLA Target (min)', 'SLA Status',
        'Source', 'Notes'
    ])
    for inc in Incident.objects.select_related('assigned_to').all().order_by('-started_at'):
        writer.writerow([
            inc.incident_id, inc.title, inc.asset_name, inc.ip_address or 'N/A',
            inc.severity, inc.status,
            inc.assigned_to.username if inc.assigned_to else 'Unassigned',
            inc.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            inc.acknowledged_at.strftime('%Y-%m-%d %H:%M:%S') if inc.acknowledged_at else 'N/A',
            inc.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if inc.resolved_at else 'N/A',
            inc.response_time_minutes if inc.response_time_minutes is not None else 'N/A',
            inc.resolution_time_minutes if inc.resolution_time_minutes is not None else 'N/A',
            inc.sla_target_minutes,
            inc.sla_status,
            inc.source,
            inc.notes,
        ])
    return response


@login_required(login_url='login')
def api_incident_export_pdf(request):
    """Export incidents as PDF (falls back to printable HTML if reportlab unavailable)."""
    from django.http import HttpResponse as HR
    try:
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        REPORTLAB_AVAILABLE = True
    except ImportError:
        REPORTLAB_AVAILABLE = False

    incidents = Incident.objects.select_related('assigned_to').all().order_by('-started_at')

    if not REPORTLAB_AVAILABLE:
        rows = ''.join(
            f"<tr><td>{i.incident_id}</td><td>{i.title}</td><td>{i.severity}</td>"
            f"<td>{i.status}</td><td>{i.assigned_to.username if i.assigned_to else 'N/A'}</td>"
            f"<td>{i.started_at.strftime('%Y-%m-%d %H:%M')}</td>"
            f"<td>{i.response_time_minutes if i.response_time_minutes is not None else 'N/A'} min</td>"
            f"<td>{i.resolution_time_minutes if i.resolution_time_minutes is not None else 'N/A'} min</td>"
            f"<td>{i.sla_status}</td></tr>"
            for i in incidents
        )
        html = f"""<!DOCTYPE html><html><head><title>Incident Report</title>
        <style>body{{font-family:Arial,sans-serif;padding:20px}}h1{{color:#c00}}
        table{{width:100%;border-collapse:collapse;margin-top:20px;font-size:11px}}
        th,td{{border:1px solid #ddd;padding:6px;text-align:left}}
        th{{background:#f2f2f2}}tr:nth-child(even){{background:#f9f9f9}}</style></head>
        <body onload="window.print()"><h1>Monitor OS — Incident Response Report</h1>
        <p>Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table><thead><tr><th>Incident ID</th><th>Title</th><th>Severity</th><th>Status</th>
        <th>Assigned To</th><th>Started At</th><th>Response (min)</th>
        <th>Resolution (min)</th><th>SLA</th></tr></thead><tbody>{rows}</tbody></table>
        </body></html>"""
        return HR(html, content_type='text/html')

    response = HR(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="incidents.pdf"'
    doc = SimpleDocTemplate(response, pagesize=landscape(letter), rightMargin=20, leftMargin=20, topMargin=30, bottomMargin=20)
    story = []
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=16,
                                 textColor=colors.HexColor('#ef4444'), spaceAfter=12)
    story.append(Paragraph("Monitor OS — Incident Response Report", title_style))
    story.append(Paragraph(f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 12))
    headers = ['ID', 'Title', 'Severity', 'Status', 'Assigned', 'Started', 'Resp(min)', 'Resol(min)', 'SLA']
    data = [[Paragraph(f'<b>{h}</b>', styles['Normal']) for h in headers]]
    for inc in incidents[:100]:
        data.append([
            Paragraph(inc.incident_id, styles['Normal']),
            Paragraph(inc.title[:40], styles['Normal']),
            Paragraph(inc.severity, styles['Normal']),
            Paragraph(inc.status, styles['Normal']),
            Paragraph(inc.assigned_to.username if inc.assigned_to else 'N/A', styles['Normal']),
            Paragraph(inc.started_at.strftime('%Y-%m-%d %H:%M'), styles['Normal']),
            Paragraph(str(inc.response_time_minutes) if inc.response_time_minutes is not None else 'N/A', styles['Normal']),
            Paragraph(str(inc.resolution_time_minutes) if inc.resolution_time_minutes is not None else 'N/A', styles['Normal']),
            Paragraph(inc.sla_status, styles['Normal']),
        ])
    table = Table(data, colWidths=[80, 120, 55, 70, 70, 90, 55, 55, 50])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f2f2f2')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
    ]))
    story.append(table)
    doc.build(story)
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ─── Vulnerability Management Module ─────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


@login_required(login_url='login')
def vulnerability_list_view(request):
    """
    Main vulnerability management page.
    Supports search, severity, status, and scanner filters with pagination.
    """
    profile = _get_or_create_profile(request.user)

    q        = request.GET.get('q', '').strip()
    severity = request.GET.get('severity', '').strip()
    status   = request.GET.get('status', '').strip()
    scanner  = request.GET.get('scanner', '').strip()
    page_num = request.GET.get('page', 1)

    qs = Vulnerability.objects.all()

    if q:
        qs = qs.filter(
            Q(asset_ip__icontains=q) |
            Q(hostname__icontains=q) |
            Q(title__icontains=q) |
            Q(cve__icontains=q) |
            Q(description__icontains=q)
        )
    if severity:
        qs = qs.filter(severity=severity)
    if status:
        qs = qs.filter(status=status)
    if scanner:
        qs = qs.filter(scanner__icontains=scanner)

    paginator = Paginator(qs, 25)
    page_obj  = paginator.get_page(page_num)

    # Metrics for header cards
    total_vulns    = Vulnerability.objects.count()
    critical_count = Vulnerability.objects.filter(severity='Critical', status='Open').count()
    high_count     = Vulnerability.objects.filter(severity='High', status='Open').count()
    open_count     = Vulnerability.objects.filter(status='Open').count()
    resolved_count = Vulnerability.objects.filter(status='Resolved').count()

    # Unique scanner values for filter dropdown
    scanners = list(Vulnerability.objects.values_list('scanner', flat=True).distinct().order_by('scanner'))

    return render(request, 'vulnerability_list.html', {
        'username':       request.user.username,
        'avatar_url':     profile.get_avatar_url(),
        'page_obj':       page_obj,
        'q':              q,
        'severity_filter': severity,
        'status_filter':  status,
        'scanner_filter': scanner,
        'total_vulns':    total_vulns,
        'critical_count': critical_count,
        'high_count':     high_count,
        'open_count':     open_count,
        'resolved_count': resolved_count,
        'scanners':       scanners,
        'severity_choices': VULN_SEVERITY_CHOICES,
        'status_choices':   VULN_STATUS_CHOICES,
    })


@login_required(login_url='login')
def vulnerability_detail_view(request, pk):
    """Full detail view for a single vulnerability record."""
    from django.shortcuts import get_object_or_404
    profile = _get_or_create_profile(request.user)
    vuln    = get_object_or_404(Vulnerability, pk=pk)
    return render(request, 'vulnerability_detail.html', {
        'username':   request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'vuln':       vuln,
    })


@login_required(login_url='login')
@csrf_exempt
def api_add_vulnerability(request):
    """
    POST  — creates a new manual vulnerability entry.
    Accepts JSON body with all vulnerability fields.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        body = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    asset_ip = (body.get('asset_ip') or '').strip()
    title    = (body.get('title') or '').strip()

    if not asset_ip or not title:
        return JsonResponse({'error': 'asset_ip and title are required'}, status=400)

    # Validate IP
    import ipaddress
    try:
        ipaddress.ip_address(asset_ip)
    except ValueError:
        return JsonResponse({'error': 'Invalid IP address'}, status=400)

    # Parse CVSS safely
    cvss_raw = body.get('cvss')
    cvss = None
    if cvss_raw not in (None, ''):
        try:
            cvss = float(str(cvss_raw))
            if not (0.0 <= cvss <= 10.0):
                return JsonResponse({'error': 'CVSS must be 0.0–10.0'}, status=400)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Invalid CVSS value'}, status=400)

    now = timezone.now()

    try:
        vuln, created = Vulnerability.objects.get_or_create(
            asset_ip=asset_ip,
            title=title,
            defaults={
                'hostname':      body.get('hostname', ''),
                'description':   body.get('description', ''),
                'cve':           body.get('cve', ''),
                'cvss':          cvss,
                'severity':      body.get('severity', 'Medium'),
                'scanner':       body.get('scanner', 'Manual'),
                'status':        body.get('status', 'Open'),
                'solution':      body.get('solution', ''),
                'reference_url': body.get('reference_url', ''),
                'evidence':      body.get('evidence', ''),
                'first_seen':    now,
                'last_seen':     now,
                'created_at':    now,
            }
        )
        if not created:
            # Update last_seen and mutable fields
            vuln.last_seen   = now
            vuln.hostname    = body.get('hostname', vuln.hostname)
            vuln.description = body.get('description', vuln.description)
            vuln.cve         = body.get('cve', vuln.cve)
            vuln.cvss        = cvss if cvss is not None else vuln.cvss
            vuln.severity    = body.get('severity', vuln.severity)
            vuln.scanner     = body.get('scanner', vuln.scanner)
            vuln.status      = body.get('status', vuln.status)
            vuln.solution    = body.get('solution', vuln.solution)
            vuln.reference_url = body.get('reference_url', vuln.reference_url)
            vuln.evidence    = body.get('evidence', vuln.evidence)
            vuln.save()
    except Exception as exc:
        return JsonResponse({'error': str(exc)}, status=500)

    return JsonResponse({
        'success': True,
        'created': created,
        'id':      vuln.pk,
        'message': 'Vulnerability created.' if created else 'Vulnerability updated (last_seen refreshed).'
    })


@login_required(login_url='login')
def api_vulnerabilities_for_ip(request):
    """
    GET ?ip=<ip>  — returns JSON list of vulnerability summaries for the
    given IP, consumed by the Device Intelligence modal on the dashboard.
    """
    ip = request.GET.get('ip', '').strip()
    if not ip:
        return JsonResponse({'error': 'ip parameter required'}, status=400)

    vulns = Vulnerability.objects.filter(asset_ip=ip).order_by('-severity', '-last_seen')
    data = [
        {
            'id':          v.pk,
            'title':       v.title,
            'cve':         v.cve,
            'cvss':        str(v.cvss) if v.cvss is not None else 'N/A',
            'severity':    v.severity,
            'status':      v.status,
            'first_seen':  v.first_seen.strftime('%Y-%m-%d'),
            'last_seen':   v.last_seen.strftime('%Y-%m-%d'),
            'detail_url':  f'/vulnerabilities/{v.pk}/',
        }
        for v in vulns
    ]
    return JsonResponse({'success': True, 'count': len(data), 'vulnerabilities': data})


@login_required(login_url='login')
def api_vulnerability_metrics(request):
    """
    GET — returns summary counts used by the dashboard sidebar vulnerability card.
    """
    total    = Vulnerability.objects.count()
    open_c   = Vulnerability.objects.filter(status='Open').count()
    critical = Vulnerability.objects.filter(severity='Critical').count()
    high     = Vulnerability.objects.filter(severity='High').count()
    resolved = Vulnerability.objects.filter(status='Resolved').count()
    return JsonResponse({
        'total':    total,
        'open':     open_c,
        'critical': critical,
        'high':     high,
        'resolved': resolved,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ─── Incident Remediation Enhancements ─────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

from .models import IncidentEvidence, IncidentComments

@login_required(login_url='login')
@csrf_exempt
def api_update_remediation_info(request, pk):
    """Update remediation details before incident is closed."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)
    
    try:
        incident = Incident.objects.get(pk=pk)
        if incident.status == 'Closed':
            return JsonResponse({'success': False, 'error': 'Cannot update closed incidents'}, status=400)
        
        body = json.loads(request.body)
        incident.patch_applied = body.get('patch_applied', '').strip()
        incident.configuration_changes = body.get('configuration_changes', '').strip()
        incident.commands_executed = body.get('commands_executed', '').strip()
        incident.version_before = body.get('version_before', '').strip()
        incident.version_after = body.get('version_after', '').strip()
        incident.remediation_summary = body.get('remediation_summary', '').strip()
        incident.save()
        
        return JsonResponse({'success': True, 'message': 'Remediation details updated successfully.'})
    except Incident.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Incident not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required(login_url='login')
@csrf_exempt
def api_verify_remediation(request, pk):
    """Verify remediation of a resolved incident. Reopens if verification fails."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)
    
    try:
        incident = Incident.objects.get(pk=pk)
        if incident.status != 'Resolved':
            return JsonResponse({'success': False, 'error': 'Incident must be Resolved to verify remediation'}, status=400)
        
        body = json.loads(request.body)
        status = body.get('verification_status', '').strip()
        notes = body.get('verification_notes', '').strip()
        
        if status not in ('Successful', 'Failed', 'Needs Rework'):
            return JsonResponse({'success': False, 'error': 'Invalid verification status'}, status=400)
        
        incident.verification_status = status
        incident.verification_notes = notes
        incident.verified_by = request.user
        incident.verification_date = timezone.now()
        
        if status in ('Failed', 'Needs Rework'):
            incident.status = 'Reopened'
            
        incident.save()
        
        return JsonResponse({
            'success': True,
            'status': incident.status,
            'verification_status': incident.verification_status,
            'message': 'Verification updated successfully.'
        })
    except Incident.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Incident not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required(login_url='login')
@csrf_exempt
def api_add_comment(request, pk):
    """Add a comment/activity log entry to an incident."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)
    
    try:
        incident = Incident.objects.get(pk=pk)
        body = json.loads(request.body)
        comment_text = body.get('comment', '').strip()
        
        if not comment_text:
            return JsonResponse({'success': False, 'error': 'Comment content is required'}, status=400)
        
        comment = IncidentComments.objects.create(
            incident=incident,
            user=request.user,
            comment=comment_text,
            timestamp=timezone.now()
        )
        
        return JsonResponse({
            'success': True,
            'comment': {
                'id': comment.pk,
                'user': comment.user.username,
                'comment': comment.comment,
                'timestamp': comment.timestamp.strftime('%d %b %H:%M')
            }
        })
    except Incident.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Incident not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required(login_url='login')
@csrf_exempt
def api_upload_evidence(request, pk):
    """Upload evidence file (Images, PDF, TXT, LOG, ZIP)."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)
    
    try:
        incident = Incident.objects.get(pk=pk)
        uploaded_file = request.FILES.get('file')
        
        if not uploaded_file:
            return JsonResponse({'success': False, 'error': 'No file uploaded'}, status=400)
        
        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if ext not in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.pdf', '.txt', '.log', '.zip'):
            return JsonResponse({'success': False, 'error': 'Disallowed file extension'}, status=400)
        
        evidence = IncidentEvidence.objects.create(
            incident=incident,
            file=uploaded_file,
            filename=uploaded_file.name,
            uploaded_by=request.user,
            uploaded_at=timezone.now()
        )
        
        return JsonResponse({
            'success': True,
            'evidence': {
                'id': evidence.pk,
                'filename': evidence.filename,
                'uploaded_by': evidence.uploaded_by.username if evidence.uploaded_by else 'System',
                'uploaded_at': evidence.uploaded_at.strftime('%Y-%m-%d %H:%M:%S'),
                'url': evidence.file.url
            }
        })
    except Incident.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Incident not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required(login_url='login')
@csrf_exempt
def api_delete_evidence(request, ev_pk):
    """Delete evidence file (Admins / Staff only)."""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST required'}, status=405)
    
    if not (request.user.is_superuser or request.user.is_staff):
         return JsonResponse({'success': False, 'error': 'Permission denied. Admins only.'}, status=403)
         
    try:
        evidence = IncidentEvidence.objects.get(pk=ev_pk)
        
        if evidence.file and os.path.isfile(evidence.file.path):
            try:
                os.remove(evidence.file.path)
            except Exception:
                pass
            
        evidence.delete()
        return JsonResponse({'success': True, 'message': 'Evidence deleted successfully.'})
    except IncidentEvidence.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Evidence not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)