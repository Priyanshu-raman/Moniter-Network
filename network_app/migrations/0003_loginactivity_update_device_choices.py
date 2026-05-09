import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('network_app', '0002_loginactivity_userprofile'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── LoginActivity: make user nullable, add username_attempt, update event choices ──
        migrations.AlterField(
            model_name='loginactivity',
            name='user',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='login_activity',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name='loginactivity',
            name='username_attempt',
            field=models.CharField(blank=True, default='', max_length=150),
        ),
        migrations.AlterField(
            model_name='loginactivity',
            name='event',
            field=models.CharField(
                choices=[
                    ('LOGIN', 'Login'),
                    ('LOGOUT', 'Logout'),
                    ('FAILED', 'Failed Login'),
                ],
                max_length=10,
            ),
        ),
        # ── Device: update device_type to use defined choices ──
        migrations.AlterField(
            model_name='device',
            name='device_type',
            field=models.CharField(
                choices=[
                    ('PC', 'PC'),
                    ('Mobile', 'Mobile'),
                    ('Router', 'Router'),
                    ('Switch', 'Switch'),
                    ('Gateway', 'Gateway'),
                    ('Workstation', 'Workstation'),
                    ('Server', 'Server'),
                    ('Database', 'Database'),
                    ('Unknown', 'Unknown'),
                ],
                default='PC',
                max_length=50,
            ),
        ),
    ]
