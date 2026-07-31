from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from config_manager import config_mgr
import string

class DynamicPasswordPolicyValidator:
    def validate(self, password, user=None):
        config_mgr.load()
        min_len = config_mgr.get("security.password_policy_settings.min_length", 8)
        try:
            min_len = int(min_len)
        except (ValueError, TypeError):
            min_len = 8
            
        if len(password) < min_len:
            raise ValidationError(
                _("This password is too short. It must contain at least %(min_length)d characters."),
                code='password_too_short',
                params={'min_length': min_len},
            )

        require_special = config_mgr.get("security.password_policy_settings.require_special", True)
        if require_special:
            # Check if there is at least one special character (non-alphanumeric or standard punctuation)
            special_chars = set(string.punctuation)
            if not any(char in special_chars for char in password):
                raise ValidationError(
                    _("This password must contain at least one special character."),
                    code='password_no_special',
                )

    def get_help_text(self):
        config_mgr.load()
        min_len = config_mgr.get("security.password_policy_settings.min_length", 8)
        try:
            min_len = int(min_len)
        except (ValueError, TypeError):
            min_len = 8
        require_special = config_mgr.get("security.password_policy_settings.require_special", True)
        
        help_text = _("Your password must contain at least %(min_length)d characters.") % {'min_length': min_len}
        if require_special:
            help_text += " " + _("It must also contain at least one special character.")
        return help_text
