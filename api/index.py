"""
SMS SENTINEL — Vercel Serverless Entry Point
Exposes the existing Flask application as a WSGI handler for Vercel Python runtime.
Includes WSGI middleware to normalize PATH_INFO when requests are rewritten by Vercel.
"""

import os
import sys

# Add repository root to system path so existing app, model, and database modules import cleanly
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app


class VercelWSGIMiddleware:
    """
    WSGI Middleware to normalize PATH_INFO on Vercel deployments.
    When Vercel rewrites incoming requests (e.g. /, /login, /api/predict) to /api/index.py,
    the client's true requested path is provided in headers like x-matched-path or x-forwarded-uri.
    This middleware extracts the real client path and sets environ['PATH_INFO']
    so Flask routing matches the intended route seamlessly.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Check Vercel routing headers in priority order
        matched_path = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_VERCEL_PATH")
            or environ.get("HTTP_X_ORIGINAL_URI")
            or environ.get("HTTP_X_REWRITE_URL")
        )

        if matched_path:
            # Strip any URL query parameters if present
            path_only = matched_path.split("?")[0]
            environ["PATH_INFO"] = path_only
        else:
            # 2. Fallback: If PATH_INFO contains the /api/index.py rewrite target, strip the prefix
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith("/api/index.py"):
                stripped = path_info[len("/api/index.py"):]
                environ["PATH_INFO"] = stripped if stripped.startswith("/") else ("/" + stripped)
            elif path_info.startswith("/api/index"):
                stripped = path_info[len("/api/index"):]
                environ["PATH_INFO"] = stripped if stripped.startswith("/") else ("/" + stripped)

        return self.wsgi_app(environ, start_response)


# Wrap Flask WSGI callable with path normalization middleware
app.wsgi_app = VercelWSGIMiddleware(app.wsgi_app)

# Expose WSGI handler aliases
handler = app
application = app

# Vercel serverless function entrypoint
if __name__ == "__main__":
    app.run()

