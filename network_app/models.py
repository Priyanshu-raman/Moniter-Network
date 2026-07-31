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
    ip_address   = models.GenericIPAddressField()
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
    os           = models.CharField(max_length=100, default='Unknown')
    vendor       = models.CharField(max_length=100, default='Unknown')
    firewall     = models.CharField(max_length=50, default='Unknown')
    rogue        = models.CharField(max_length=50, default='Normal')
    alert        = models.CharField(max_length=50, default='OK')
    inactive     = models.CharField(max_length=50, default='0')
    hostname     = models.CharField(max_length=100, default='Unknown')

    def __str__(self):
        return self.ip_address


class ScanSession(models.Model):
    timestamp      = models.DateTimeField(default=timezone.now)
    network_subnet = models.CharField(max_length=100, blank=True, default='')
    devices        = models.ManyToManyField('Device', related_name='scan_sessions')

    def __str__(self):
        return f"Scan Session at {self.timestamp} on {self.network_subnet}"


class UserProfile(models.Model):
    user       = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    email      = models.EmailField(blank=True, default='')
    bio        = models.TextField(blank=True, default='')
    avatar     = models.ImageField(upload_to='avatars/', blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, default='')
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
    EVENT_SCAN         = 'SCAN'
    EVENT_ESCALATE     = 'ESCALATE'

    EVENT_CHOICES = [
        (EVENT_LOGIN,        'Login'),
        (EVENT_LOGOUT,       'Logout'),
        (EVENT_FAILED_LOGIN, 'Failed Login'),
        (EVENT_SCAN,         'Network Scan'),
        (EVENT_ESCALATE,     'Escalation'),
    ]

    user       = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='login_activity',
        null=True, blank=True,          # null for failed logins with unknown usernames
    )
    username_attempt = models.CharField(max_length=150, blank=True, default='')
    event      = models.CharField(max_length=10, choices=EVENT_CHOICES)
    timestamp  = models.DateTimeField(default=timezone.now)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
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
    level_1_email = models.EmailField(blank=True, default='')
    level_2_email = models.EmailField(blank=True, default='')
    level_3_email = models.EmailField(blank=True, default='')
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


# ── Asset Management Module Models ──────────────────────────────────────────

CRITICALITY_CHOICES = [
    ('Critical', 'Critical 🔴'),
    ('High',     'High 🟠'),
    ('Medium',   'Medium 🟡'),
    ('Low',      'Low 🟢'),
]

ASSET_STATUS_CHOICES = [
    ('Active',         'Active'),
    ('Inactive',       'Inactive'),
    ('Maintenance',    'Under Maintenance'),
    ('Decommissioned', 'Decommissioned'),
]


class Asset(models.Model):
    asset_name       = models.CharField(max_length=150, unique=True)
    asset_type       = models.CharField(max_length=80)
    description      = models.TextField(blank=True, default='')

    # Ownership Information
    owner_name       = models.CharField(max_length=120)
    owner_email      = models.EmailField()
    owner_contact    = models.CharField(max_length=25, validators=[phone_validator], blank=True, default='')

    # Business Information
    department       = models.CharField(max_length=100)
    location         = models.CharField(max_length=120)
    business_unit    = models.CharField(max_length=100)
    criticality      = models.CharField(max_length=15, choices=CRITICALITY_CHOICES, default='Low')

    # Technical Information
    ip_address       = models.GenericIPAddressField(null=True, blank=True)
    mac_address      = models.CharField(max_length=17, blank=True, default='')
    operating_system = models.CharField(max_length=100, blank=True, default='')
    vendor           = models.CharField(max_length=100, blank=True, default='')
    model            = models.CharField(max_length=100, blank=True, default='')
    serial_number    = models.CharField(max_length=100, blank=True, default='')

    # Additional Information
    purchase_date    = models.DateField(null=True, blank=True)
    warranty_expiry  = models.DateField(null=True, blank=True)
    status           = models.CharField(max_length=20, choices=ASSET_STATUS_CHOICES, default='Active')
    notes            = models.TextField(blank=True, default='')

    # Audit & Relationships
    added_by         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='assets_added')
    created_at       = models.DateTimeField(default=timezone.now)
    updated_at       = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['asset_name']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['criticality']),
        ]

    def __str__(self):
        return f'{self.asset_name} ({self.asset_type})'

    def get_importance_score(self):
        """Map criticality to a numeric score from 0 to 100."""
        score_map = {
            'Critical': 100,
            'High': 80,
            'Medium': 50,
            'Low': 20,
        }
        return score_map.get(self.criticality, 0)

    def get_potential_impact(self):
        """Map criticality to a potential impact description."""
        impact_map = {
            'Critical': 'Total loss of critical operations, compliance violation, or severe financial loss.',
            'High': 'Interruption of major business units or significant operational impact.',
            'Medium': 'Partial operational delay or inconvenience, moderate impact.',
            'Low': 'Negligible business operations impact, localized or minimal.',
        }
        return impact_map.get(self.criticality, 'Unknown')


class Notification(models.Model):
    LEVEL_CHOICES = [
        ('Low',      'Low'),
        ('Medium',   'Medium'),
        ('High',     'High'),
        ('Critical', 'Critical'),
    ]

    title      = models.CharField(max_length=150)
    message    = models.TextField()
    level      = models.CharField(max_length=15, choices=LEVEL_CHOICES, default='Low')
    type       = models.CharField(max_length=50, default='Notification')
    created_at = models.DateTimeField(default=timezone.now)
    is_read    = models.BooleanField(default=False)
    read_at    = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'[{self.level}] {self.title}'


class AlertEvent(models.Model):
    STATUS_CHOICES = [
        ('New', 'New'),
        ('Active', 'Active'),
        ('Acknowledged', 'Acknowledged'),
        ('Investigating', 'Investigating'),
        ('Resolved', 'Resolved'),
        ('Closed', 'Closed'),
        ('Archived', 'Archived'),
        ('Suppressed', 'Suppressed'),
    ]

    alert_type        = models.CharField(max_length=50)  # e.g., "Device Offline", "Manual"
    severity          = models.CharField(max_length=20)  # Low, Medium, High, Critical
    asset_name        = models.CharField(max_length=150, blank=True, default='N/A')
    ip_address        = models.GenericIPAddressField(null=True, blank=True)
    message           = models.TextField()
    status            = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')

    # Timestamps & Downtime
    created_at        = models.DateTimeField(default=timezone.now)
    resolved_at       = models.DateTimeField(null=True, blank=True)
    downtime_duration = models.CharField(max_length=50, blank=True, default='')

    # Origin & Tracking
    alert_source      = models.CharField(max_length=50, default='Scanner')  # Scanner, Manual
    assigned_user     = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_alerts')

    # Counters & Cooldowns
    occurrence_count  = models.IntegerField(default=1)
    suppression_count = models.IntegerField(default=0)
    first_detected    = models.DateTimeField(default=timezone.now)
    last_seen         = models.DateTimeField(default=timezone.now)
    cooldown_expiry   = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'[{self.severity}] {self.ip_address or "System"} - {self.alert_type} ({self.status})'


# ── Incident Response Center ─────────────────────────────────────────────────

INCIDENT_STATUS_CHOICES = [
    ('New',           'New'),
    ('Active',        'Active'),
    ('Acknowledged',  'Acknowledged'),
    ('Investigating', 'Investigating'),
    ('Resolved',      'Resolved'),
    ('Closed',        'Closed'),
    ('Reopened',      'Reopened'),
]

INCIDENT_SEVERITY_CHOICES = [
    ('Critical', 'Critical 🔴'),
    ('High',     'High 🟠'),
    ('Medium',   'Medium 🟡'),
    ('Low',      'Low 🟢'),
]

# Default SLA targets per severity (minutes)
SLA_DEFAULTS = {
    'Critical': 30,
    'High':     60,
    'Medium':   240,
    'Low':      480,
}


class Incident(models.Model):
    # Auto-generated ID like INC-20260614-0001
    incident_id   = models.CharField(max_length=30, unique=True, editable=False)
    title         = models.CharField(max_length=200)
    asset_name    = models.CharField(max_length=150, blank=True, default='N/A')
    ip_address    = models.GenericIPAddressField(null=True, blank=True)
    severity      = models.CharField(max_length=20, choices=INCIDENT_SEVERITY_CHOICES, default='Medium')
    status        = models.CharField(max_length=20, choices=INCIDENT_STATUS_CHOICES, default='New')

    # Assignment
    assigned_to   = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_incidents'
    )

    # Optional link to an existing AlertEvent
    alert_event   = models.ForeignKey(
        AlertEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name='incidents'
    )

    # Timestamps
    started_at      = models.DateTimeField(default=timezone.now)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at     = models.DateTimeField(null=True, blank=True)
    closed_at       = models.DateTimeField(null=True, blank=True)

    # SLA
    sla_target_minutes = models.IntegerField(default=60)

    # Notes / description
    notes  = models.TextField(blank=True, default='')
    source = models.CharField(max_length=50, default='Manual')  # Manual, Scanner, Alert

    # Target due date / Remediation Info / Verification Info
    due_date              = models.DateTimeField(null=True, blank=True)
    patch_applied         = models.CharField(max_length=255, blank=True, default='')
    configuration_changes = models.TextField(blank=True, default='')
    commands_executed     = models.TextField(blank=True, default='')
    version_before        = models.CharField(max_length=50, blank=True, default='')
    version_after         = models.CharField(max_length=50, blank=True, default='')
    remediation_summary   = models.TextField(blank=True, default='')

    verification_status   = models.CharField(
        max_length=50,
        choices=[('Successful', 'Successful'), ('Failed', 'Failed'), ('Needs Rework', 'Needs Rework')],
        blank=True,
        default=''
    )
    verified_by           = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_incidents'
    )
    verification_date     = models.DateTimeField(null=True, blank=True)
    verification_notes    = models.TextField(blank=True, default='')

    # History & Logs
    assignment_history    = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
            models.Index(fields=['started_at']),
        ]

    def save(self, *args, **kwargs):
        # Auto-generate incident_id on first save
        if not self.incident_id:
            from django.utils import timezone as tz
            today = tz.now().strftime('%Y%m%d')
            count = Incident.objects.filter(incident_id__startswith=f'INC-{today}-').count() + 1
            self.incident_id = f'INC-{today}-{count:04d}'
        # Auto-set SLA target from severity if not already set
        if self.sla_target_minutes == 60 and self.severity in SLA_DEFAULTS:
            self.sla_target_minutes = SLA_DEFAULTS[self.severity]
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.incident_id}: {self.title} [{self.severity}] ({self.status})'

    # ── Computed Properties ──────────────────────────────────────────────────

    @property
    def response_time_minutes(self):
        """Minutes from started_at to acknowledged_at."""
        if self.acknowledged_at and self.started_at:
            delta = self.acknowledged_at - self.started_at
            return max(0, int(delta.total_seconds() / 60))
        return None

    @property
    def resolution_time_minutes(self):
        """Minutes from started_at to resolved_at."""
        if self.resolved_at and self.started_at:
            delta = self.resolved_at - self.started_at
            return max(0, int(delta.total_seconds() / 60))
        return None

    @property
    def sla_status(self):
        """Met / Breached / Pending based on resolution time vs SLA target."""
        if self.resolved_at is None:
            # Still open — check if already past SLA
            from django.utils import timezone as tz
            elapsed = int((tz.now() - self.started_at).total_seconds() / 60)
            return 'Breached' if elapsed > self.sla_target_minutes else 'Pending'
        if self.resolution_time_minutes is not None:
            return 'Met' if self.resolution_time_minutes <= self.sla_target_minutes else 'Breached'
        return 'Pending'

    @property
    def timeline_events(self):
        """Ordered list of timeline events for this incident."""
        events = [{'time': self.started_at, 'label': 'Incident Created', 'icon': 'alert-triangle', 'color': '#ef4444'}]
        if self.acknowledged_at:
            events.append({'time': self.acknowledged_at, 'label': f'Acknowledged by {self.assigned_to.username if self.assigned_to else "System"}', 'icon': 'check-circle', 'color': '#f59e0b'})
        if self.status == 'Investigating' and self.acknowledged_at:
            events.append({'time': self.acknowledged_at, 'label': 'Investigation Started', 'icon': 'search', 'color': '#3b82f6'})
        if self.resolved_at:
            events.append({'time': self.resolved_at, 'label': 'Incident Resolved', 'icon': 'shield-check', 'color': '#339933'})
        if self.closed_at:
            events.append({'time': self.closed_at, 'label': 'Incident Closed', 'icon': 'archive', 'color': '#6b7280'})

        # Assignment changes from history
        for record in self.assignment_history:
            try:
                from django.utils.dateparse import parse_datetime
                dt = parse_datetime(record['time'])
                if dt:
                    events.append({
                        'time': dt,
                        'label': f"Assigned to {record['assigned_to']} by {record['assigned_by']}",
                        'icon': 'user-plus',
                        'color': '#8b5cf6'
                    })
            except Exception:
                pass

        # Verification event
        if self.verification_date:
            label = f"Verification {self.verification_status}"
            icon = 'shield-alert'
            color = '#f59e0b'
            if self.verification_status == 'Successful':
                label = 'Verification Successful'
                icon = 'shield-check'
                color = '#339933'
            elif self.verification_status in ('Failed', 'Needs Rework'):
                label = 'Incident Reopened after failed verification'
                icon = 'rotate-ccw'
                color = '#ef4444'
            
            events.append({
                'time': self.verification_date,
                'label': label,
                'icon': icon,
                'color': color
            })

        return sorted(events, key=lambda e: e['time'])

    @property
    def days_remaining(self):
        if not self.due_date:
            return None
        delta = self.due_date - timezone.now()
        if delta.total_seconds() < 0:
            return 0
        return round(delta.total_seconds() / 86400, 1)

    @property
    def is_overdue(self):
        if not self.due_date:
            return False
        # Only overdue if not resolved/closed (or just generally overdue, let's check both: if status in Resolved/Closed, is it overdue? Usually "Target Resolution Date" applies to active incidents, but let's check status != Resolved/Closed)
        if self.status in ('Resolved', 'Closed'):
            return False
        return self.due_date < timezone.now()


# ── Vulnerability Management ──────────────────────────────────────────────────

VULN_SEVERITY_CHOICES = [
    ('Critical', 'Critical'),
    ('High',     'High'),
    ('Medium',   'Medium'),
    ('Low',      'Low'),
    ('Info',     'Info'),
]

VULN_STATUS_CHOICES = [
    ('Open',          'Open'),
    ('In Progress',   'In Progress'),
    ('Resolved',      'Resolved'),
    ('False Positive','False Positive'),
]


class Vulnerability(models.Model):
    """
    Stores a single vulnerability finding, either discovered automatically
    during a network scan or entered manually by an analyst.
    """
    asset_ip      = models.GenericIPAddressField(db_index=True)
    hostname      = models.CharField(max_length=255, blank=True, default='')
    title         = models.CharField(max_length=300)
    description   = models.TextField(blank=True, default='')
    cve           = models.CharField(max_length=30,  blank=True, default='',
                                     help_text='e.g. CVE-2021-41773')
    cvss          = models.DecimalField(max_digits=4, decimal_places=1,
                                        null=True, blank=True,
                                        help_text='CVSS score 0.0 – 10.0')
    severity      = models.CharField(max_length=15, choices=VULN_SEVERITY_CHOICES,
                                     default='Medium')
    scanner       = models.CharField(max_length=100, default='Manual',
                                     help_text='Scanner that found this (nmap, Manual, etc.)')
    status        = models.CharField(max_length=20, choices=VULN_STATUS_CHOICES,
                                     default='Open')
    solution      = models.TextField(blank=True, default='')
    reference_url = models.URLField(max_length=500, blank=True, default='')
    evidence      = models.TextField(blank=True, default='',
                                     help_text='Raw output / evidence notes')

    # Timestamps
    first_seen  = models.DateTimeField(default=timezone.now)
    last_seen   = models.DateTimeField(default=timezone.now)
    created_at  = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['asset_ip']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['cve']),
        ]
        # Unique on (asset_ip, title) so we can upsert instead of duplicating
        unique_together = [('asset_ip', 'title')]

    def __str__(self):
        cve_part = f' [{self.cve}]' if self.cve else ''
        return f'[{self.severity}] {self.asset_ip}{cve_part} — {self.title}'

    @property
    def severity_color(self):
        return {
            'Critical': '#ef4444',
            'High':     '#f59e0b',
            'Medium':   '#eab308',
            'Low':      '#3b82f6',
            'Info':     '#6b7280',
        }.get(self.severity, '#6b7280')

    @property
    def status_color(self):
        return {
            'Open':           '#ef4444',
            'In Progress':    '#f59e0b',
            'Resolved':       '#339933',
            'False Positive': '#6b7280',
        }.get(self.status, '#6b7280')


# ── Incident Remediation Extensions ───────────────────────────────────────────

import os

class IncidentEvidence(models.Model):
    incident    = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='evidences')
    file        = models.FileField(upload_to='evidences/')
    filename    = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    uploaded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'IncidentEvidence'
        ordering = ['uploaded_at']

    def __str__(self):
        return f'{self.filename} for {self.incident.incident_id}'

    @property
    def is_image(self):
        ext = os.path.splitext(self.filename)[1].lower()
        return ext in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')

    @property
    def is_previewable(self):
        ext = os.path.splitext(self.filename)[1].lower()
        return ext in ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.pdf', '.txt', '.log')


class IncidentComments(models.Model):
    incident   = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='comments')
    user       = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    comment    = models.TextField()
    timestamp  = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'IncidentComments'
        ordering = ['timestamp']

    def __str__(self):
        return f'Comment by {self.user.username if self.user else "System"} on {self.incident.incident_id}'