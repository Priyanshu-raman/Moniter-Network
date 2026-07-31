from django.test import TestCase, RequestFactory
from django.core.exceptions import ValidationError
from django.contrib.sessions.middleware import SessionMiddleware
from config_manager import config_mgr
from network_app.password_validators import DynamicPasswordPolicyValidator
from network_app.middleware import DynamicSessionTimeoutMiddleware
from network_app.email_backend import DynamicSMTPEmailBackend
import json
import os

class CentralizedConfigTests(TestCase):
    def setUp(self):
        self.original_filepath = config_mgr.filepath
        config_mgr.filepath = "config_test.json"
        self.original_config = json.dumps(config_mgr.config)
        # Write initial config
        config_mgr.save()

    def tearDown(self):
        config_mgr.filepath = self.original_filepath
        if os.path.exists("config_test.json"):
            try:
                os.remove("config_test.json")
            except:
                pass

    def test_config_manager_get_set(self):
        config_mgr.set("security.password_policy_settings.min_length", 12)
        config_mgr.save()
        self.assertEqual(config_mgr.get("security.password_policy_settings.min_length"), 12)

    def test_password_policy_validator(self):
        validator = DynamicPasswordPolicyValidator()
        
        # Test default length (8) and special character requirement
        config_mgr.set("security.password_policy_settings.min_length", 8)
        config_mgr.set("security.password_policy_settings.require_special", True)
        config_mgr.save()
        
        # Should raise validation error for too short
        with self.assertRaises(ValidationError) as context:
            validator.validate("Short1!")
        self.assertIn("too short", str(context.exception))
        
        # Should raise validation error for no special character
        with self.assertRaises(ValidationError) as context:
            validator.validate("NoSpecialPassword1")
        self.assertIn("special character", str(context.exception))
        
        # Should validate successfully
        validator.validate("ValidP@ss123")

        # Test custom length 10
        config_mgr.set("security.password_policy_settings.min_length", 10)
        config_mgr.save()
        with self.assertRaises(ValidationError):
            validator.validate("ValidP@ss")

    def test_session_timeout_middleware(self):
        middleware = DynamicSessionTimeoutMiddleware(get_response=lambda r: None)
        factory = RequestFactory()
        request = factory.get('/')
        
        # Apply session middleware to attach session to request
        session_middleware = SessionMiddleware(get_response=lambda r: None)
        session_middleware.process_request(request)
        
        config_mgr.set("security.session_timeout", 1800)
        config_mgr.save()
        middleware.process_request(request)
        
        self.assertEqual(request.session.get_expiry_age(), 1800)

    def test_dynamic_smtp_backend(self):
        config_mgr.set("alerts.smtp_server", "test.smtp.server")
        config_mgr.set("alerts.smtp_port", 999)
        config_mgr.set("alerts.email_sender", "test@sender.com")
        config_mgr.set("alerts.email_password", "testpassword")
        config_mgr.save()
        
        backend = DynamicSMTPEmailBackend()
        self.assertEqual(backend.host, "test.smtp.server")
        self.assertEqual(backend.port, 999)
        self.assertEqual(backend.username, "test@sender.com")
        self.assertEqual(backend.password, "testpassword")

    def test_scan_offline_sync(self):
        from network_app.models import Device
        # Pre-populate active device
        dev = Device.objects.create(
            ip_address="192.168.1.55",
            mac_address="aa:bb:cc:dd:ee:ff",
            role="Client Device",
            status="ACTIVE"
        )
        
        # Simulate the subnet sync logic
        import ipaddress
        network = "192.168.1.0/24"
        scanned_ips = {"192.168.1.1", "192.168.1.2"}  # Doesn't contain 192.168.1.55
        
        net = ipaddress.ip_network(network, strict=False)
        for db_dev in Device.objects.filter(status='ACTIVE'):
            ip_obj = ipaddress.ip_address(db_dev.ip_address)
            if ip_obj in net and db_dev.ip_address not in scanned_ips:
                db_dev.status = 'OFFLINE'
                db_dev.save()
                
        # Refresh and assert
        dev.refresh_from_db()
        self.assertEqual(dev.status, "OFFLINE")


class CentralizedAlertingTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        from network_app.models import Asset
        self.original_filepath = config_mgr.filepath
        config_mgr.filepath = "config_test.json"
        config_mgr.load()
        
        self.user = User.objects.create_user(username="testuser", password="testpassword")
        
        self.asset = Asset.objects.create(
            asset_name="Critical Server",
            asset_type="Server",
            owner_name="Test Owner",
            owner_email="test@owner.com",
            department="IT",
            location="Rack 1",
            business_unit="Ops",
            ip_address="192.168.1.100",
            criticality="Critical",
            added_by=self.user
        )

    def tearDown(self):
        config_mgr.filepath = self.original_filepath
        if os.path.exists("config_test.json"):
            try:
                os.remove("config_test.json")
            except:
                pass

    def test_cooldown_config_validation(self):
        config_mgr.set("cooldowns.critical", 25)
        config_mgr.save()
        self.assertEqual(config_mgr.get("cooldowns.critical"), 25)
        
        # Test validation of invalid value
        config_mgr.set("cooldowns.critical", -5)
        errors = config_mgr.validate(config_mgr.config)
        self.assertIn("cooldowns.critical: Must be a positive integer.", errors)

    def test_alert_event_creation_and_suppression(self):
        from network_app.models import AlertEvent
        from network_app.views import handle_offline_transition
        from django.utils import timezone
        
        processed_transitions = set()
        
        # Trigger offline transition for first time -> Creates new AlertEvent in Active state
        handle_offline_transition("192.168.1.100", processed_transitions)
        
        alert = AlertEvent.objects.filter(ip_address="192.168.1.100", status='Active').first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "Critical")
        self.assertEqual(alert.occurrence_count, 1)
        self.assertEqual(alert.suppression_count, 0)
        
        # Trigger offline transition again (duplication) -> Should increment occurrence & suppression and change status to Suppressed
        processed_transitions.clear()
        handle_offline_transition("192.168.1.100", processed_transitions)
        
        alert.refresh_from_db()
        self.assertEqual(alert.status, "Suppressed")
        self.assertEqual(alert.occurrence_count, 2)
        self.assertEqual(alert.suppression_count, 1)
        
        # Simulate cooldown expiry by setting cooldown_expiry to the past
        alert.cooldown_expiry = timezone.now() - timezone.timedelta(minutes=1)
        alert.save()
        
        processed_transitions.clear()
        handle_offline_transition("192.168.1.100", processed_transitions)
        
        alert.refresh_from_db()
        # Status should reset back to Active since cooldown expired and a new alert was dispatched
        self.assertEqual(alert.status, "Active")
        self.assertEqual(alert.occurrence_count, 3)
        self.assertEqual(alert.suppression_count, 1) # suppression count remains 1

    def test_alert_recovery_downtime_calculation(self):
        from network_app.models import AlertEvent
        from network_app.views import handle_offline_transition, handle_recovery_transition
        from django.utils import timezone
        
        processed_transitions = set()
        
        # Go offline
        handle_offline_transition("192.168.1.100", processed_transitions)
        alert = AlertEvent.objects.filter(ip_address="192.168.1.100", status='Active').first()
        
        # Backdate the first_detected time by 1 hour and 30 minutes
        alert.first_detected = timezone.now() - timezone.timedelta(hours=1, minutes=30)
        alert.save()
        
        # Trigger recovery transition
        processed_transitions.clear()
        handle_recovery_transition("192.168.1.100", processed_transitions)
        
        alert.refresh_from_db()
        self.assertEqual(alert.status, "Resolved")
        self.assertIsNotNone(alert.resolved_at)
        self.assertIn("1h 30m", alert.downtime_duration)


class IncidentResponseCenterTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_user(username="soc_analyst", password="password123")

    def test_incident_id_generation_and_sla_defaults(self):
        from network_app.models import Incident
        from django.utils import timezone as tz

        inc1 = Incident.objects.create(
            title="High threat alert escalation",
            severity="Critical",
            source="Alert"
        )
        # Unique INC-YYYYMMDD-0001 format
        today = tz.now().strftime('%Y%m%d')
        self.assertTrue(inc1.incident_id.startswith(f"INC-{today}-"))
        # Auto-set SLA for Critical -> 30 min
        self.assertEqual(inc1.sla_target_minutes, 30)

        inc2 = Incident.objects.create(
            title="Low threat ping failure",
            severity="Low",
            source="Manual"
        )
        # Auto-set SLA for Low -> 480 min
        self.assertEqual(inc2.sla_target_minutes, 480)

    def test_incident_sla_computation(self):
        from network_app.models import Incident
        from django.utils import timezone as tz

        # Create resolved incident within SLA (Critical: 30 min)
        inc = Incident.objects.create(
            title="Test SLA Incident",
            severity="Critical"
        )
        inc.started_at = tz.now() - tz.timedelta(minutes=40)
        # Acknowledged 10 mins after start
        inc.acknowledged_at = inc.started_at + tz.timedelta(minutes=10)
        # Resolved 25 mins after start (within SLA limit of 30 mins)
        inc.resolved_at = inc.started_at + tz.timedelta(minutes=25)
        inc.save()

        self.assertEqual(inc.response_time_minutes, 10)
        self.assertEqual(inc.resolution_time_minutes, 25)
        self.assertEqual(inc.sla_status, "Met")

        # Create resolved incident breaching SLA
        inc_breach = Incident.objects.create(
            title="Test Breached SLA",
            severity="Critical"
        )
        inc_breach.started_at = tz.now() - tz.timedelta(minutes=45)
        inc_breach.resolved_at = inc_breach.started_at + tz.timedelta(minutes=35) # > 30 minutes
        inc_breach.save()

        self.assertEqual(inc_breach.sla_status, "Breached")

    def test_ajax_update_incident_status(self):
        from network_app.models import Incident
        from django.urls import reverse
        
        inc = Incident.objects.create(
            title="Samba Vulnerability Detected",
            severity="High",
            assigned_to=None
        )

        self.client.login(username="soc_analyst", password="password123")
        url = reverse("incident_update_status")
        
        # Test Acknowledging incident via AJAX
        payload = {
            "incident_id": inc.pk,
            "status": "Acknowledged",
            "assigned_to_id": self.user.pk,
            "notes": "Acknowledged detection and started logs triage."
        }
        response = self.client.post(
            url,
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        resp_data = response.json()
        self.assertTrue(resp_data["success"])
        self.assertEqual(resp_data["status"], "Acknowledged")

        inc.refresh_from_db()
        self.assertEqual(inc.status, "Acknowledged")
        self.assertIsNotNone(inc.acknowledged_at)
        self.assertEqual(inc.assigned_to, self.user)
