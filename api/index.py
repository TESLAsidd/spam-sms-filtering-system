"""
SMS SENTINEL — Vercel Serverless Entry Point
Exposes the existing Flask application as a WSGI handler for Vercel Python runtime.
"""

import os
import sys

# Add repository root to system path so existing app, model, and database modules import cleanly
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

# Vercel serverless function entrypoint
if __name__ == "__main__":
    app.run()
