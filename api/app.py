import os
from flask import Flask
from routes import main

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)

app.secret_key = 'threatlens-ai-secret-key-2024-secure-local-only'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['JSON_SORT_KEYS'] = False

app.register_blueprint(main)

