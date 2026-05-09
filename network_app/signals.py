from django.db.models.signals import post_migrate
from django.dispatch import receiver
from .models import GlobalSettings

@receiver(post_migrate)
def create_default_global_settings(sender, **kwargs):
    # Only run for our app to prevent duplicate executions
    if sender.name == 'network_app':
        # Create the default GlobalSettings row if it doesn't already exist
        # pk=1 ensures it's the singular instance
        GlobalSettings.objects.get_or_create(
            pk=1,
            defaults={
                'default_ip_range': '192.168.1.0/24',
                'scan_interval': '300'  # 5 minutes
            }
        )
