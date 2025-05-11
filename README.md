Fusion API


Fusion API is a modular Flask-based framework designed to simplify building OAuth2-compatible APIs with JWT authentication, user management, and extensible versioned route handling. It powers production backends like cbpapi.com and AI logistics platforms.


✨ Features
✅ JWT authentication with token revocation and expiration
🔐 Support for API Key, Basic Auth, and JSON-based login
🧑‍💼 Admin-only routes and token/user management
🧠 Usage logging for auditing and analytics
🌐 Environment-based configuration with .env
🦺 Optional Slack notifications on startup or events
🧱 Easily extensible with Flask Blueprints


📦 Installation 
git clone https://github.com/GameFusion/fusion-api.git
cd fusion-api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt 


⚙️ Environment Setup


Create a .env file (if not already) and set: 
API_DOMAIN_NAME=api.yourdomain.com
JWT_SECRET_KEY=your_jwt_secret
JWT_TOKEN_EXPIRY_HOURS=2

# SSL paths
SSL_CERT_PATH=/path/to/fullchain.pem
SSL_KEY_PATH=/path/to/privkey.pem

# Slack (optional)
SLACK_BOT_TOKEN=xoxb-xxx
SLACK_CHANNEL=general

# PostgreSQL
DATABASE_URL=postgresql://user:pass@host:port/dbname 


🚀 Run 
python main.py 
Or with SSL: 
python main.py --ssl 


🛠️ Key Files 
File
Description
main.py
Main app entry point and route setup
database.py
Handles DB connections and operations
slack_message.py
Sends Slack messages via bot integration
startup_notifier.py
Sends Slack message when app boots
user_manager.py
Create and manage users/API keys
requirements.txt
Python dependencies



📘 API Endpoints
/api/v1/auth/login: Login via API Key, Basic Auth, or JSON
/api/v1/auth/logout: Revoke current JWT token
/api/v1/routes: List all routes
/api/v1/test: Test endpoint (no auth)
/api/v1/ping: Check if API is alive
/api/v1/admin/...: Admin endpoints (users, tokens, usage)


🔐 Admin Login Example 
curl -X POST https://api.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"secret"}' 


📝 License


This project is MIT Licensed.
