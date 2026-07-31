from django.utils.deprecation import MiddlewareMixin
from config_manager import config_mgr

class DynamicSessionTimeoutMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if hasattr(request, 'session'):
            config_mgr.load()
            timeout = config_mgr.get("security.session_timeout", 3600)
            try:
                timeout_sec = int(timeout)
                # Set expiry dynamically for this request/session
                request.session.set_expiry(timeout_sec)
            except Exception as e:
                print(f"[DynamicSessionTimeoutMiddleware] Error setting expiry: {e}")
