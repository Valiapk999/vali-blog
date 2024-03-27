#!/bin/bash

# Start Gunicorn processes
echo Starting Gunicorn.
exec gunicorn --reload helloworld.helloworld.wsgi:application \
    --bind 0.0.0.0:8000
