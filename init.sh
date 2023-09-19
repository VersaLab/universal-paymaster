#!/bin/sh
python manage.py makemigrations paymaster
python manage.py migrate
python manage.py loaddata paymaster/configs/ApprovedTokensInfo.json
python manage.py collectstatic --no-input
DJANGO_SUPERUSER_USERNAME=$SUPER_USER_NAME DJANGO_SUPERUSER_PASSWORD=$SUPER_USER_PASSWORD DJANGO_SUPERUSER_EMAIL=$SUPER_USER_EMAIL python manage.py createsuperuser --noinput
gunicorn paymaster.wsgi:application --bind 0.0.0.0:8080