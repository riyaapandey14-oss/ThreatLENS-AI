import sys
import os
sys.path.insert(0, './.vscode')

from app import create_app

app = create_app()

# Vercel requires WSGI callable
if __name__ == "__main__":
    app.run()

