"""
SMS SENTINEL — Vercel Serverless Entry Point
Exposes the existing Flask application as a WSGI handler for Vercel Python runtime.
Includes WSGI middleware to normalize PATH_INFO when requests are rewritten by Vercel.
"""

import os
import sys
import urllib.parse

# Add repository root to system path so existing app, model, and database modules import cleanly
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app


class VercelWSGIMiddleware:
    """
    WSGI Middleware to normalize PATH_INFO on Vercel deployments.
    When Vercel rewrites incoming requests to /api/index.py?__vercel_path=/$1,
    this middleware extracts the real client path and sets environ['PATH_INFO']
    so Flask routing matches the intended route seamlessly.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Check query string for __vercel_path parameter
        query_string = environ.get("QUERY_STRING", "")
        if "__vercel_path=" in query_string:
            params = urllib.parse.parse_qs(query_string)
            if "__vercel_path" in params and params["__vercel_path"]:
                target_path = params["__vercel_path"][0]
                if not target_path.startswith("/"):
                    target_path = "/" + target_path
                # Clean up query string so Flask and views see only user query params
                remaining = {k: v for k, v in params.items() if k != "__vercel_path"}
                environ["QUERY_STRING"] = urllib.parse.urlencode(remaining, doseq=True)
                environ["PATH_INFO"] = target_path
                return self.wsgi_app(environ, start_response)

        # 2. Check Vercel routing headers
        matched = (
            environ.get("HTTP_X_MATCHED_PATH")
            or environ.get("HTTP_X_FORWARDED_URI")
            or environ.get("HTTP_X_VERCEL_PATH")
            or environ.get("HTTP_X_ORIGINAL_URI")
            or environ.get("HTTP_X_REWRITE_URL")
        )

        if matched:
            path_only = matched.split("?")[0]
            environ["PATH_INFO"] = path_only
        else:
            path_info = environ.get("PATH_INFO", "")
            if path_info.startswith("/api/index.py"):
                stripped = path_info[len("/api/index.py"):]
                environ["PATH_INFO"] = stripped if stripped.startswith("/") else ("/" + stripped)
            elif path_info.startswith("/api/index"):
                stripped = path_info[len("/api/index"):]
                environ["PATH_INFO"] = stripped if stripped.startswith("/") else ("/" + stripped)
            elif path_info in ("/api", "/api/"):
                environ["PATH_INFO"] = "/"

        return self.wsgi_app(environ, start_response)


# Wrap Flask WSGI callable with path normalization middleware
app.wsgi_app = VercelWSGIMiddleware(app.wsgi_app)

# Expose WSGI handler aliases
handler = app
application = app

# Vercel serverless function entrypoint
if __name__ == "__main__":
    app.run()

