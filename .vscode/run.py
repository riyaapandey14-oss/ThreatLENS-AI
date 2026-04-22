from app import create_app, db

app = create_app()

@app.cli.command()
def initdb():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
    print('Database tables created!')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Auto-create tables on first run
    app.run(debug=True, host='0.0.0.0', port=5000)
