"""
Gunicorn configuration for Cyber Threat Exchange.

The APScheduler is started inside the master process (on_starting hook) so
that it is never killed by worker timeouts or worker recycling.
"""

import os

import django

workers = int(os.getenv("WEB_CONCURRENCY", 4))

