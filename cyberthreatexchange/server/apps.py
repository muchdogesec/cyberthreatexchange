from django.apps import AppConfig


class ServerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cyberthreatexchange.server'
    label = 'cyberthreatexchange'

    def ready(self):
        import sys
        # Only start the scheduler in the Django dev server (runserver).
        # For gunicorn, it is started in the master process via gunicorn.conf.py.
        if len(sys.argv) > 1 and sys.argv[1] == "runserver":
            from cyberthreatexchange.server import scheduler
            scheduler.start()
