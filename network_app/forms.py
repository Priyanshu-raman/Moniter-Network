from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import ITContact, GlobalSettings, CONTACT_ROLE_CHOICES, SCAN_INTERVAL_CHOICES


class ITContactForm(forms.ModelForm):
    class Meta:
        model  = ITContact
        fields = ['name', 'role', 'email', 'contact_number']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'settings-input',
                'placeholder': 'Full name',
                'autocomplete': 'off',
            }),
            'role': forms.Select(attrs={
                'class': 'settings-select',
            }),
            'email': forms.EmailInput(attrs={
                'class': 'settings-input',
                'placeholder': 'email@company.com',
            }),
            'contact_number': forms.TextInput(attrs={
                'class': 'settings-input',
                'placeholder': '+1 555 000 0000',
            }),
        }


class GlobalSettingsForm(forms.ModelForm):
    class Meta:
        model  = GlobalSettings
        fields = ['default_ip_range', 'scan_interval']
        widgets = {
            'default_ip_range': forms.TextInput(attrs={
                'class': 'settings-input',
                'placeholder': '192.168.1.0/24',
            }),
            'scan_interval': forms.Select(attrs={
                'class': 'settings-select',
            }),
        }

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('email',)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user
