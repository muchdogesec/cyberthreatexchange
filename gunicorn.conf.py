"""
Gunicorn configuration for Cyber Threat Exchange.

The APScheduler is started inside the master process (on_starting hook) so
that it is never killed by worker timeouts or worker recycling.
"""

import django


def on_starting(server):
    """Called once in the gunicorn master process before workers are forked."""
    import os
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cyberthreatexchange.settings")
    django.setup()

    from cyberthreatexchange.server import scheduler
    scheduler.start()


def worker_exit(server, worker):
    """Ensure APScheduler threads don't leak if a worker somehow holds a ref."""
    pass
