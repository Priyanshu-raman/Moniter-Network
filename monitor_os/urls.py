from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from network_app import views

urlpatterns = [
    path('admin/',         admin.site.urls),
    path('',               views.login_view,       name='login'),
    path('login/',         views.login_view),
    path('signup/',        views.signup_view,       name='signup'),
    path('logout/',        views.logout_view,       name='logout'),
    path('start/',         views.landing_view,      name='landing'),

    # ── Dashboard ────────────────────────────────────────────────────
    path('dashboard/',     views.dashboard_view,    name='dashboard'),

    # ── API: scan proxy (Django → Flask scanner) ─────────────────────────
    path('api/scan/',      views.api_scan_proxy,   name='api_scan'),
    path('api/network-info/', views.api_network_info, name='api_network_info'),

    # ── API: granular device-asset counts  ───────────────────────────
    path('api/device-assets/', views.api_device_assets, name='api_device_assets'),

    # ── Security logs (audit trail) ──────────────────────────────────
    path('security-logs/', views.security_logs_view, name='security_logs'),

    # ── Broadcast ────────────────────────────────────────────────────
    path('broadcast/',     views.broadcast_view,    name='broadcast'),

    # ── Network map ──────────────────────────────────────────────────
    path('network-map/',   views.network_map_view,  name='network_map'),

    # ── Profile / Account ────────────────────────────────────────────
    path('account/',       views.account_view,      name='account'),
    path('edit-profile/',  views.edit_profile_view, name='edit_profile'),

    # ── Settings (blank canvas) ──────────────────────────────────────
    path('settings/',      views.settings_view,     name='settings'),

    # ── Assets ───────────────────────────────────────────────────────
    path('assets/',        views.asset_list_view,   name='asset_list'),
    path('assets/add/',    views.asset_create_view, name='asset_create'),
    path('assets/<int:pk>/', views.asset_detail_view, name='asset_detail'),
    path('assets/<int:pk>/edit/', views.asset_edit_view, name='asset_edit'),
    path('assets/<int:pk>/delete/', views.asset_delete_view, name='asset_delete'),
    path('assets/export/', views.asset_export_view, name='asset_export'),
    path('api/notifications/', views.api_notifications, name='api_notifications'),
    path('api/notifications/mark-read/', views.api_mark_notifications_read, name='api_mark_notifications_read'),

    # ── Configuration panel ──────────────────────────────────────────
    path('config/',        views.config_view,       name='config'),
    path('api/config/',    views.api_config_endpoint, name='api_config'),
    path('api/config/export/', views.api_config_export, name='api_config_export'),
    path('api/config/restore/', views.api_config_restore, name='api_config_restore'),

    # ── Alert History and Exporters ──────────────────────────────────────────
    path('alerts/',        views.alerts_history_view, name='alerts_history'),
    path('alerts/<int:pk>/resolve/', views.api_resolve_alert, name='api_resolve_alert'),
    path('api/alert-metrics/', views.api_alert_metrics, name='api_alert_metrics'),
    path('api/alerts/export/csv/', views.alerts_export_csv, name='alerts_export_csv'),
    path('api/alerts/export/pdf/', views.alerts_export_pdf, name='alerts_export_pdf'),

    # ── Incident Response Center ─────────────────────────────────────────────
    path('incidents/',                views.incident_response_view,     name='incident_response'),
    path('incidents/create/',         views.incident_create_view,       name='incident_create'),
    path('incidents/<int:pk>/',       views.incident_detail_view,       name='incident_detail'),
    path('api/incidents/update-status/', views.incident_update_status_view, name='incident_update_status'),
    path('api/incident-metrics/',     views.api_incident_metrics,       name='api_incident_metrics'),
    path('api/incidents/export/csv/', views.api_incident_export_csv,    name='api_incident_export_csv'),
    path('api/incidents/export/pdf/', views.api_incident_export_pdf,    name='api_incident_export_pdf'),

    # Incident Remediation Enhancements
    path('api/incidents/<int:pk>/remediation/', views.api_update_remediation_info, name='api_update_remediation'),
    path('api/incidents/<int:pk>/verify/',      views.api_verify_remediation,      name='api_verify_remediation'),
    path('api/incidents/<int:pk>/comment/',     views.api_add_comment,             name='api_add_comment'),
    path('api/incidents/<int:pk>/evidence/upload/', views.api_upload_evidence,     name='api_upload_evidence'),
    path('api/incidents/evidence/<int:ev_pk>/delete/', views.api_delete_evidence,  name='api_delete_evidence'),

    path("__reload__/",    include("django_browser_reload.urls")),

    # ── Vulnerability Management ──────────────────────────────────────────────
    path('vulnerabilities/',              views.vulnerability_list_view,       name='vulnerability_list'),
    path('vulnerabilities/<int:pk>/',     views.vulnerability_detail_view,     name='vulnerability_detail'),
    path('api/vulnerabilities/add/',      views.api_add_vulnerability,         name='api_add_vulnerability'),
    path('api/vulnerabilities/for-ip/',   views.api_vulnerabilities_for_ip,   name='api_vulnerabilities_for_ip'),
    path('api/vulnerability-metrics/',    views.api_vulnerability_metrics,     name='api_vulnerability_metrics'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)