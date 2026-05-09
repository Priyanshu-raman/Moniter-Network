from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import RegexValidator


# ── Device categories ────────────────────────────────────────────────────────

DEVICE_TYPE_CHOICES = [
    ('PC',          'PC'),
    ('Mobile',      'Mobile'),
    ('Router',      'Router'),
    ('Switch',      'Switch'),
    ('Gateway',     'Gateway'),
    ('Workstation', 'Workstation'),
    ('Server',      'Server'),
    ('Database',    'Database'),
    ('Unknown',     'Unknown'),
]


class Device(models.Model):
    ip_address   = models.GenericIPAddressField(unique=True)
    mac_address  = models.CharField(max_length=17, default='Unknown')
    role         = models.CharField(max_length=50, default='Client Device')
    device_type  = models.CharField(
        max_length=50,
        choices=DEVICE_TYPE_CHOICES,
        default='PC',
    )
    last_seen    = models.DateTimeField(default=timezone.now)
    status       = models.CharField(max_length=20, default='ACTIVE')
    ports        = models.JSONField(default=list)

    def __str__(self):
        return self.ip_address


class UserProfile(models.Model):
    user       = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    email      = models.EmailField(blank=True, default='')
    bio        = models.TextField(blank=True, default='')
    avatar     = models.ImageField(upload_to='avatars/', blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'Profile of {self.user.username}'

    def get_avatar_url(self):
        if self.avatar and self.avatar.name:
            return self.avatar.url
        return f'https://api.dicebear.com/7.x/avataaars/svg?seed={self.user.username}'


class LoginActivity(models.Model):
    EVENT_LOGIN        = 'LOGIN'
    EVENT_LOGOUT       = 'LOGOUT'
    EVENT_FAILED_LOGIN = 'FAILED'

    EVENT_CHOICES = [
        (EVENT_LOGIN,        'Login'),
        (EVENT_LOGOUT,       'Logout'),
        (EVENT_FAILED_LOGIN, 'Failed Login'),
    ]

    user       = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='login_activity',
        null=True, blank=True,          # null for failed logins with unknown usernames
    )
    username_attempt = models.CharField(max_length=150, blank=True, default='')
    event      = models.CharField(max_length=10, choices=EVENT_CHOICES)
    timestamp  = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True, default='')

    class Meta:
        ordering = ['-timestamp']


    def __str__(self):
        name = self.user.username if self.user else self.username_attempt or '(unknown)'
        return f'{name} — {self.event} at {self.timestamp}'


# ── IT & Security Contact Directory ─────────────────────────────────────────

CONTACT_ROLE_CHOICES = [
    ('CISO',       'CISO'),
    ('IT_MGMT',    'IT Management'),
    ('STAFF',      'Staff Member'),
    ('SOC',        'SOC Analyst'),
    ('NETADMIN',   'Network Admin'),
    ('SYSADMIN',   'System Admin'),
    ('HELPDESK',   'Help Desk'),
]

phone_validator = RegexValidator(
    regex=r'^\+?[\d\s\-\(\)]{7,20}$',
    message='Enter a valid phone number (7–20 digits, spaces, dashes allowed).',
)


class ITContact(models.Model):
    name           = models.CharField(max_length=120)
    role           = models.CharField(max_length=20, choices=CONTACT_ROLE_CHOICES, default='STAFF')
    email          = models.EmailField()
    contact_number = models.CharField(max_length=25, validators=[phone_validator], blank=True, default='')
    created_at     = models.DateTimeField(default=timezone.now)
    updated_at     = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['role', 'name']

    def __str__(self):
        return f'{self.name} ({self.get_role_display()})'


# ── Global Dashboard Settings (singleton) ───────────────────────────────────

SCAN_INTERVAL_CHOICES = [
    ('30',  '30 Seconds'),
    ('60',  '1 Minute'),
    ('300', '5 Minutes'),
    ('600', '10 Minutes'),
]

SUBNET_VALIDATOR = RegexValidator(
    regex=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',
    message='Enter a valid CIDR subnet (e.g. 192.168.1.0/24).',
)


class GlobalSettings(models.Model):
    """
    Singleton model — always use GlobalSettings.get_instance() to access.
    Only one row should ever exist (pk=1).
    """
    default_ip_range = models.CharField(
        max_length=50,
        default='192.168.1.0/24',
        validators=[SUBNET_VALIDATOR],
        help_text='Default CIDR subnet used when the dashboard loads.',
    )
    scan_interval = models.CharField(
        max_length=5,
        choices=SCAN_INTERVAL_CHOICES,
        default='60',
        help_text='How often the dashboard auto-scans (seconds).',
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name        = 'Global Settings'
        verbose_name_plural = 'Global Settings'

    def __str__(self):
        return 'Global Dashboard Settings'

    @classmethod
    def get_instance(cls):
        """Return (or create) the single settings row."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj