from django.contrib import admin
from .models import Device, UserProfile, LoginActivity, ITContact, GlobalSettings


@admin.register(ITContact)
class ITContactAdmin(admin.ModelAdmin):
    list_display  = ('name', 'role', 'email', 'contact_number', 'updated_at')
    list_filter   = ('role',)
    search_fields = ('name', 'email')
    ordering      = ('role', 'name')


@admin.register(GlobalSettings)
class GlobalSettingsAdmin(admin.ModelAdmin):
    list_display = ('default_ip_range', 'scan_interval', 'updated_at')

    def has_add_permission(self, request):
        # Enforce singleton — only one row allowed
        return not GlobalSettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False  # Never allow deletion of the singleton


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display  = ('ip_address', 'mac_address', 'role', 'device_type', 'status', 'last_seen')
    list_filter   = ('status', 'device_type')
    search_fields = ('ip_address', 'mac_address', 'role')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display  = ('user', 'email', 'created_at')
    search_fields = ('user__username', 'email')


@admin.register(LoginActivity)
class LoginActivityAdmin(admin.ModelAdmin):
    list_display  = ('username_attempt', 'event', 'ip_address', 'timestamp')
    list_filter   = ('event',)
    search_fields = ('username_attempt', 'ip_address')
    readonly_fields = ('user', 'username_attempt', 'event', 'timestamp', 'ip_address', 'user_agent')
