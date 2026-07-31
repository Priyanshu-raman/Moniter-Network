from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('network_app', '0008_alertevent'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Incident',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('incident_id', models.CharField(editable=False, max_length=30, unique=True)),
                ('title', models.CharField(max_length=200)),
                ('asset_name', models.CharField(blank=True, default='N/A', max_length=150)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('severity', models.CharField(
                    choices=[
                        ('Critical', 'Critical 🔴'),
                        ('High', 'High 🟠'),
                        ('Medium', 'Medium 🟡'),
                        ('Low', 'Low 🟢'),
                    ],
                    default='Medium',
                    max_length=20,
                )),
                ('status', models.CharField(
                    choices=[
                        ('New', 'New'),
                        ('Active', 'Active'),
                        ('Acknowledged', 'Acknowledged'),
                        ('Investigating', 'Investigating'),
                        ('Resolved', 'Resolved'),
                        ('Closed', 'Closed'),
                    ],
                    default='New',
                    max_length=20,
                )),
                ('started_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('acknowledged_at', models.DateTimeField(blank=True, null=True)),
                ('resolved_at', models.DateTimeField(blank=True, null=True)),
                ('closed_at', models.DateTimeField(blank=True, null=True)),
                ('sla_target_minutes', models.IntegerField(default=60)),
                ('notes', models.TextField(blank=True, default='')),
                ('source', models.CharField(default='Manual', max_length=50)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('assigned_to', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='assigned_incidents',
                    to='auth.user',
                )),
                ('alert_event', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='incidents',
                    to='network_app.alertevent',
                )),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='incident',
            index=models.Index(fields=['status'], name='network_app_incide_status_idx'),
        ),
        migrations.AddIndex(
            model_name='incident',
            index=models.Index(fields=['severity'], name='network_app_incide_sev_idx'),
        ),
        migrations.AddIndex(
            model_name='incident',
            index=models.Index(fields=['started_at'], name='network_app_incide_start_idx'),
        ),
    ]
