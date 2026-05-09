#!/bin/bash
set -e

echo "==> Collecting static files..."
python manage.py collectstatic --noinput

echo "==> Running Django migrations..."
python manage.py migrate --noinput

echo "==> Creating superuser if not exists..."
python manage.py createsuperuser --noinput || echo "Superuser already exists, skipping."

echo "==> Starting Flask API on port 5000..."
python app.py &

echo "==> Starting Django with Gunicorn..."
gunicorn monitor_os.wsgi:application --bind 0.0.0.0:${PORT:-8080} --workers 2 --timeout 120
