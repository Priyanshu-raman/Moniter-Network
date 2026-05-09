from django.apps import AppConfig


class NetworkAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'network_app'

    def ready(self):
        import network_app.signals
