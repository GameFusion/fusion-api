# app_notifier.py
from api_notifier import ApiNotifier
import database
import time

# Create and start the API notifier
notifier = ApiNotifier(
    db_connection_func=database.get_db_connection,
    slack_channel="#general",
    notify_all=True
)

# Start the notifier in a background thread
notifier_thread = notifier.start()

print("API Notifier service started. Press Ctrl+C to stop.")

try:
    # Keep the main thread alive
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    notifier.stop()
    print("API Notifier service stopped.")