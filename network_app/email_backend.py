from django.core.mail.backends.smtp import EmailBackend
from config_manager import config_mgr

class DynamicSMTPEmailBackend(EmailBackend):
    def __init__(self, host=None, port=None, username=None, password=None,
                 use_tls=None, fail_silently=False, use_ssl=None, timeout=None,
                 ssl_keyfile=None, ssl_certfile=None, **kwargs):
        # Reload configuration to ensure we have the latest updates
        config_mgr.load()
        
        host = host or config_mgr.get("alerts.smtp_server", "smtp.gmail.com")
        
        try:
            port = port or int(config_mgr.get("alerts.smtp_port", 587))
        except (ValueError, TypeError):
            port = 587
            
        username = username or config_mgr.get("alerts.email_sender", "priyanshupri25@gmail.com")
        password = password or config_mgr.get("alerts.email_password", "kygfclwiebnaxpqn")
        
        # We default use_tls to True as is standard for port 587
        if use_tls is None:
            use_tls = True
            
        super().__init__(host=host, port=port, username=username, password=password,
                         use_tls=use_tls, fail_silently=fail_silently, use_ssl=use_ssl, timeout=timeout,
                         ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile, **kwargs)
