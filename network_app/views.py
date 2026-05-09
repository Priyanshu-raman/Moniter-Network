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
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt

from .models import Device, LoginActivity, UserProfile, ITContact, GlobalSettings
from .forms  import ITContactForm, GlobalSettingsForm, CustomUserCreationForm


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
    return ROLE_TO_TYPE.get(role, 'Unknown')


# ─── API: scan proxy (forwards to Flask, saves to Django DB) ─────────────────

@login_required(login_url='login')
def api_scan_proxy(request):
    """
    Accepts POST {network: '...'}, forwards to Flask scanner on port 5000,
    saves results into the Django Device table, then returns the JSON.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

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
        with urllib.request.urlopen(req, timeout=120) as resp:
            devices = json.loads(resp.read().decode('utf-8'))
    except urllib.error.URLError as e:
        return JsonResponse({
            'error': f'Flask scanner is not running or unreachable. Start app.py first. ({e.reason})'
        }, status=503)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    # ── Persist results in Django Device table ────────────────────────────
    for d in devices:
        ip = d.get('ip')
        if not ip:
            continue
        device_type = _role_to_device_type(d.get('role', ''))
        Device.objects.update_or_create(
            ip_address=ip,
            defaults={
                'mac_address':  d.get('mac', 'Unknown') or 'Unknown',
                'role':         d.get('role', 'Client Device'),
                'device_type':  device_type,
                'status':       d.get('status', 'ACTIVE'),
                'ports':        d.get('ports', []),
                'last_seen':    timezone.now(),
            },
        )

    return JsonResponse(devices, safe=False)


# ─── auth ───────────────────────────────────────────────────────────────────

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
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
            return redirect('landing')
        else:
            # Log failed login attempt
            username_attempt = request.POST.get('username', '')
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
            return redirect('landing')
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
    return render(request, 'landing.html')


@login_required(login_url='login')
def dashboard_view(request):
    network = request.GET.get('network', '')
    profile = _get_or_create_profile(request.user)
    return render(request, 'dashboard.html', {
        'username':   request.user.username,
        'network':    network,
        'avatar_url': profile.get_avatar_url(),
    })


# ─── API: granular asset counts ─────────────────────────────────────────────

@login_required(login_url='login')
def api_device_assets(request):
    """
    Returns a JSON object with counts of active devices in each category.
    The dashboard's Network Assets widget polls this endpoint.
    """
    active_devices = Device.objects.filter(status='ACTIVE')

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

            if new_username and new_username != request.user.username:
                if User.objects.filter(username=new_username).exclude(pk=request.user.pk).exists():
                    error = 'Username already taken.'
                else:
                    request.user.username = new_username
                    request.user.save()

            if new_email:
                profile.email = new_email
            profile.bio = new_bio

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
    Groups scanned devices into logical subnet zones and passes JSON to the
    Vis.js network-map frontend.
    """
    profile = _get_or_create_profile(request.user)
    devices = Device.objects.filter(status='ACTIVE')

    # Build zone → [devices] mapping
    zones: dict[str, dict] = {}

    for device in devices:
        zone_info = _get_zone(device.ip_address)
        zone_name = zone_info['name']

        if zone_name not in zones:
            zones[zone_name] = {
                'name':    zone_name,
                'color':   zone_info['color'],
                'devices': [],
            }
        zones[zone_name]['devices'].append({
            'id':          device.pk,
            'ip':          device.ip_address,
            'mac':         device.mac_address,
            'role':        device.role,
            'device_type': device.device_type,
            'status':      device.status,
        })

    zones_json = json.dumps(list(zones.values()))

    return render(request, 'network_map.html', {
        'username':   request.user.username,
        'avatar_url': profile.get_avatar_url(),
        'zones_json': zones_json,
    })