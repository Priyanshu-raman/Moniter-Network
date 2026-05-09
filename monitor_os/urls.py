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

    path("__reload__/",    include("django_browser_reload.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)