"""
ThreatLens AI - Entry Point
Complete Flask application for rule-based cybersecurity analysis.
No external APIs, no database - intelligent local analysis engine.

Features:
- Password strength analyzer
- URL safety scanner
- Phishing email detector
- Cyber knowledge base
- Security quiz
"""
from flask import Flask
from routes import main

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Configuration
app.secret_key = 'threatlens-ai-secret-key-2024-secure-local-only'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload
app.config['JSON_SORT_KEYS'] = False

# Register blueprints
app.register_blueprint(main)

# Run server
if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║          🛡️  ThreatLens AI - Starting  🛡️            ║
    ║     Rule-based Cybersecurity Analysis Engine         ║
    ║                                                       ║
    ║   Server running on http://localhost:5000            ║
    ║   Press Ctrl+C to stop                              ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)

