#!/bin/sh

echo "Creating database..."
python create_db.py

echo "Starting Flask app..."
gunicorn --bind 0.0.0.0:5001 app:app