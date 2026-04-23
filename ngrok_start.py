from pyngrok import ngrok
import subprocess
import time
import atexit
import os

print("Starting Flask app...")
# Start Flask in background
flask_process = subprocess.Popen(["python", ".vscode/run.py"])

# Wait for Flask to start
time.sleep(5)

# Create ngrok tunnel
public_url = ngrok.connect(5000, bind_tls=True)
print(f"Public URL: {public_url}")

# Cleanup on exit
def cleanup():
    ngrok.kill()
    flask_process.terminate()
atexit.register(cleanup)

# Keep running
input("Press Enter to stop...")

