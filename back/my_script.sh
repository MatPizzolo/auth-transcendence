#!/bin/bash

python3 -m venv django_venv

source django_venv/bin/activate

pip install --upgrade pip

pip install django
pip install psycopg2-binary

pip freeze > requirements.txt

pip install --upgrade pip

pip install -r requirements.txt

# START PROJECT;; START APP
django-admin startproject backend


# Deactivate the virtual environment
deactivate
