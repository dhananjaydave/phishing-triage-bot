"""WSGI entrypoint for production servers (gunicorn etc). See Procfile."""

from triage.web import app, init_app

init_app()

if __name__ == "__main__":
    app.run()
