from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import ITContact, GlobalSettings, CONTACT_ROLE_CHOICES, SCAN_INTERVAL_CHOICES, Asset


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
        fields = ['default_ip_range', 'scan_interval', 'level_1_email', 'level_2_email', 'level_3_email']
        widgets = {
            'default_ip_range': forms.TextInput(attrs={
                'class': 'settings-input',
                'placeholder': '192.168.1.0/24',
            }),
            'scan_interval': forms.Select(attrs={
                'class': 'settings-select',
            }),
            'level_1_email': forms.EmailInput(attrs={
                'class': 'settings-input',
                'placeholder': 'soc-l1@company.com',
            }),
            'level_2_email': forms.EmailInput(attrs={
                'class': 'settings-input',
                'placeholder': 'soc-l2@company.com',
            }),
            'level_3_email': forms.EmailInput(attrs={
                'class': 'settings-input',
                'placeholder': 'ciso@company.com',
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


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        exclude = ['added_by', 'created_at', 'updated_at']
        widgets = {
            'asset_name': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. SOC Primary Firewall', 'required': 'true'}),
            'asset_type': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. Firewall, Server, Laptop', 'required': 'true'}),
            'description': forms.Textarea(attrs={'class': 'settings-input', 'rows': 3, 'placeholder': 'Provide description...'}),
            'owner_name': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'Owner Name', 'required': 'true'}),
            'owner_email': forms.EmailInput(attrs={'class': 'settings-input', 'placeholder': 'owner@company.com', 'required': 'true'}),
            'owner_contact': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': '+1 555-0199'}),
            'department': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. IT, Security, Finance', 'required': 'true'}),
            'location': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. HQ 4th Floor, AWS US-East', 'required': 'true'}),
            'business_unit': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. Security Operations', 'required': 'true'}),
            'criticality': forms.Select(attrs={'class': 'settings-select'}),
            'ip_address': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. 192.168.1.1'}),
            'mac_address': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. 00:11:22:33:44:55'}),
            'operating_system': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. Ubuntu 22.04, Windows Server 2022'}),
            'vendor': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. Cisco, Fortinet, Dell'}),
            'model': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. FortiGate 60F'}),
            'serial_number': forms.TextInput(attrs={'class': 'settings-input', 'placeholder': 'e.g. FG60F-XXXXXX'}),
            'purchase_date': forms.DateInput(attrs={'class': 'settings-input', 'type': 'date'}),
            'warranty_expiry': forms.DateInput(attrs={'class': 'settings-input', 'type': 'date'}),
            'status': forms.Select(attrs={'class': 'settings-select'}),
            'notes': forms.Textarea(attrs={'class': 'settings-input', 'rows': 3, 'placeholder': 'Additional notes...'}),
        }

    def clean_asset_name(self):
        asset_name = self.cleaned_data.get('asset_name')
        qs = Asset.objects.filter(asset_name__iexact=asset_name)
        if self.instance and self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("An asset with this name already exists.")
        return asset_name

