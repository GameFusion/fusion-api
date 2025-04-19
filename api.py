from flask import Flask, request, jsonify, Blueprint
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, decode_token, get_jwt
from flask_jwt_extended.exceptions import JWTExtendedException
from datetime import datetime, timedelta, timezone
import json
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps
import logging
import uuid
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

# Import database module using namespace
import database
import startup_notifier
import slack_message
import startup_notifier

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Get domain name from environment variables
domain_name = os.environ.get('API_DOMAIN_NAME')

# Get SSL certificate paths from environment variables
cert_path = os.environ.get('SSL_CERT_PATH')
key_path = os.environ.get('SSL_KEY_PATH')

# Create blueprints for API versioning
# this blueprint will handle all v1 API routes including authentication
api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')
jwt = JWTManager()  # global instance for decorators

# --- Initialization for embedding ---
def create_api(app: Flask) -> Flask:
    """Initialize the API inside an existing Flask app."""
    app.config.setdefault("JWT_SECRET_KEY", os.getenv("JWT_SECRET_KEY", "dev-secret-key"))
    app.config.setdefault("JWT_ACCESS_TOKEN_EXPIRES", timedelta(hours=int(os.getenv("JWT_TOKEN_EXPIRY_HOURS", "1"))))
    app.config.setdefault("JWT_TOKEN_LOCATION", ["headers"])
    app.config.setdefault("JWT_HEADER_NAME", "Authorization")
    app.config.setdefault("JWT_HEADER_TYPE", "Bearer")

    jwt.init_app(app)
    app.register_blueprint(api_v1)

    # --- New endpoint to list all available routes ---
    @app.route('/api/v1/routes', methods=['GET'])
    def list_routes():
        """Lists all registered routes for debugging purposes."""
        routes = []
        for rule in app.url_map.iter_rules():
            route = {
                'endpoint': rule.endpoint,
                'methods': list(rule.methods),
                'url': rule.rule
            }
            routes.append(route)

        return jsonify({'routes': routes})

    # Catch-all fallback route
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        logger.warning(f"Unhandled route: {path}")
        return jsonify({
            "error": "Resource not found",
            "message": "Try /api/v1/"
        }), 404

    # 404 & 500 handlers
    @app.errorhandler(404)
    def not_found(e):
        logger.warning(f"404: {request.path}")
        return jsonify({
            "error": "Resource not found",
            "message": "Try /api/v1/"
        }), 404

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"500: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

    startup_notifier.send_startup_message()
    return app

# --- For running standalone ---
def create_app() -> Flask:
    app = Flask(__name__)
    return create_api(app)


# --- token helper functions

# Add this error handler
@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    logger.error(f"Invalid token: {error_string}")
    return jsonify({
        'status': 'error',
        'message': 'Invalid token: ' + error_string
    }), 401

# JWT token blocklist setup
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if the token is in the blocklist"""
    jti = jwt_payload["jti"]
    return database.is_token_revoked(jti)

# --- Helper functions ---

def admin_required(fn):
    """Decorator to check if the user has admin role"""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        # Get username from identity
        username = get_jwt_identity()

        # Get additional claims
        claims = get_jwt()
        is_admin = claims.get('is_admin', False)
        
        if not is_admin:
            return jsonify({"msg": "Admin privileges required"}), 403
        return fn(*args, **kwargs)
    return wrapper

# --- Non-authenticated routes ---

# Add a test endpoint that doesn't require JWT
@api_v1.route('/test', methods=['GET'])
def test_endpoint():
    """Test endpoint without JWT requirement"""
    logger.info("Test endpoint accessed")

    # Log API usage (without user_id since this is unauthenticated)
    database.log_api_usage('/api/v1/test', None, request)

    return jsonify({
        "message": "Test endpoint works!",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

@api_v1.route('/ping', methods=['GET'])
def ping():
    """Simple endpoint to test JSON response"""
    logger.info("Ping erndpoint accessed")

    # Log API usage (without user_id since this is unauthenticated)
    database.log_api_usage('/api/v1/ping', None, request)
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "API is running"
    }), 200
    

# --- Authentication Routes ---

@api_v1.route('/auth/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token using API Key, Basic Auth, or JSON credentials"""
    logger.info("Authentication attempt received")
    
    try:
        user = None
        auth_method = None
        
        # 1. First check for API Key in header (highest priority)
        api_key = request.headers.get('X-API-Key') or request.headers.get('API-Key')
        if api_key:
            logger.info("API Key authentication attempt")
            auth_method = "api_key"
            # Get user from database by API key
            user = database.get_user_by_api_key(api_key)
            if not user:
                message = "Invalid API Key authentication"
                logger.warning(message)
                database.log_api_usage('/api/v1/auth/login', None, request, False, message)
                return jsonify({"error": "Invalid API Key"}), 401
        
        # 2. Then check for Basic Auth if no API Key was provided
        elif request.authorization:
            logger.info("Basic Auth authentication attempt")
            auth_method = "basic_auth"
            auth = request.authorization
            username = auth.username
            password = auth.password
            
            # Get user from database
            user = database.get_user_by_username(username)
            
            # Check password
            if not user or not check_password(password, user['password_hash']):
                message = f"Invalid Basic Auth for user: {username}"
                logger.warning(message)
                database.log_api_usage('/api/v1/auth/login', None, request, False, message)
                return jsonify({"error": "Invalid username or password"}), 401
        
        # 3. Finally check for JSON payload if neither API Key nor Basic Auth was provided
        elif request.is_json:
            logger.info("JSON credentials authentication attempt")
            auth_method = "json"
            data = request.json
            if not data:
                message = "No JSON data in request"
                logger.warning(message)
                database.log_api_usage('/api/v1/auth/login', None, request, False, message)
                return jsonify({"error": "No JSON data provided"}), 400
                
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                message = "Missing username or password in JSON"
                logger.warning(message)
                database.log_api_usage('/api/v1/auth/login', None, request, False, message)
                return jsonify({"error": "Username and password are required"}), 400
            
            logger.info(f"Login attempt for user: {username}")
            
            # Get user from database
            user = database.get_user_by_username(username)
            
            # Check password
            if not user or not check_password(password, user['password_hash']):
                message = f"Invalid login for user: {username}"
                logger.warning(message)
                database.log_api_usage('/api/v1/auth/login', None, request, False, message)
                return jsonify({"error": "Invalid username or password"}), 401
        
        else:
            message = "No authentication method provided"
            logger.warning(message)
            database.log_api_usage('/api/v1/auth/login', None, request, False, message)
            return jsonify({
                "error": "Authentication required", 
                "methods": ["API Key", "Basic Auth", "JSON credentials"]
            }), 401
        
        # Check if user is active
        if not user['active']:
            message = f"Authentication failed - User is inactive"
            logger.warning(message)
            database.log_api_usage('/api/v1/auth/login', None, request, False, message)
            return jsonify({"error": "Account is inactive"}), 403
        
        # Set identity and include additional claims
        username = user['username']
        is_admin = user['role'] == 'admin'
        
        # Create token with additional claims
        expires_delta = timedelta(hours=int(os.getenv('JWT_TOKEN_EXPIRY_HOURS', '1')))
        expires_at = datetime.now(timezone.utc) + expires_delta
        
        access_token = create_access_token(
            identity=username,
            additional_claims={
                "is_admin": is_admin,
                "user_id": user['id'],
                "auth_method": auth_method
            },
            expires_delta=expires_delta
        )
        
        # Get the JTI (JWT Token Identifier) from the token payload
        import jwt
        decoded = jwt.decode(
            access_token, 
            options={"verify_signature": False}
        )
        jti = decoded['jti']
        
        # Log the token in the database
        database.create_token_record(user['id'], jti, expires_at, request)
        
        message = f"Authentication successful for user: {username} via {auth_method}"
        # After successful login, update the API usage with the actual user ID
        database.log_api_usage('/api/v1/auth/login', user['id'], request, True, message)
        
        logger.info(message)
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": int(expires_delta.total_seconds())
        }), 200
        
    except Exception as e:
        message = f"Authentication error: {str(e)}"
        logger.error(message)
        database.log_api_usage('/api/v1/auth/login', user['id'], request, True, message)
        return jsonify({"error": f"Authentication failed: {str(e)}"}), 500


# For checking a password against a hash
def check_password(password, password_hash):
    """Check if password matches hash using Werkzeug's check_password_hash"""
    try:
        return check_password_hash(password_hash, password)
    except Exception as e:
        logger.error(f"Password check error: {str(e)}")
        return False

@api_v1.route('/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    """Revoke the current token"""
    try:
        # Get username and user_id from JWT
        username = get_jwt_identity()
        claims = get_jwt()
        user_id = claims.get('user_id')
        
        # Log API usage
        database.log_api_usage('/api/v1/auth/logout', user_id, request)
        
        # Get the JWT claims
        jti = claims["jti"]
        
        # Revoke the token
        if database.revoke_token_by_id(jti):
            return jsonify({"message": "Token revoked successfully"}), 200
        else:
            return jsonify({"error": "Failed to revoke token"}), 500
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({"error": f"Logout failed: {str(e)}"}), 500


# --- API Discovery ---


# Enhance your logging
@api_v1.before_request
def log_request_info():
    logger.info(f"Log Request Info: {request.method} {request.path}")
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        logger.info(f"Auth header present: {auth_header[:30]}...")

        # Try to manually decode the token
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            print("token", token, flush=True)
            try:
                decoded = decode_token(token)
                logger.info(f"Token decoded successfully: {decoded}")
            except JWTExtendedException as e:
                logger.error(f"JWT decode error: {str(e)}")
            except Exception as e:
                logger.error(f"Other token error: {str(e)}")
    else:
        logger.warning("No Authorization header")

    """Handle requests with Content-Type: application/json but empty body"""
    if request.method != 'GET':
        return  # Only apply this fix to GET requests
        
    if request.headers.get('Content-Type') == 'application/json' and not request.data:
        # Set request.json to an empty dict to prevent parsing errors - internal server crash
        # end users do strange stuff
        # add robust tolerance where we reasonably can
        request.data = {}

# --- Admin Routes ---

@api_v1.route('/admin/tokens', methods=['GET'])
@admin_required
def get_tokens():
    """Get all active tokens (admin only)"""
    logger.info("Admin request: get tokens")
    
    try:
        tokens = database.get_all_tokens()
        if tokens is None:
            return jsonify({"error": "Failed to retrieve tokens"}), 500
        
        return jsonify({"tokens": tokens}), 200
    except Exception as e:
        logger.error(f"Error getting tokens: {str(e)}")
        return jsonify({"error": f"Failed to get tokens: {str(e)}"}), 500

@api_v1.route('/admin/tokens/revoke', methods=['POST'])
@admin_required
def revoke_token():
    """Revoke a token (admin only)"""
    logger.info("Admin request: revoke token")
    
    try:
        data = request.json
        if not data or 'token_id' not in data:
            return jsonify({"error": "Token ID is required"}), 400
        
        token_id = data['token_id']
        
        if database.revoke_token_by_id(token_id):
            return jsonify({"message": "Token revoked successfully"}), 200
        else:
            return jsonify({"error": "Token not found or already revoked"}), 404
    except Exception as e:
        logger.error(f"Error revoking token: {str(e)}")
        return jsonify({"error": f"Failed to revoke token: {str(e)}"}), 500

@api_v1.route('/admin/users', methods=['GET'])
@admin_required
def get_users():
    """Get all users (admin only)"""
    logger.info("Admin request: get users")
    
    try:
        users = database.get_all_users()
        if users is None:
            return jsonify({"error": "Failed to retrieve users"}), 500
        
        return jsonify({"users": users}), 200
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return jsonify({"error": f"Failed to get users: {str(e)}"}), 500
    
    return jsonify(users), 200

@api_v1.route('/admin/usage_stats', methods=['GET'])
@admin_required
def get_usage_stats():
    """Get API usage statistics (admin only)"""
    logger.info("Admin request: get usage stats")
    
    try:
        stats = database.get_usage_statistics()
        if stats is None:
            return jsonify({"error": "Failed to retrieve usage statistics"}), 500
        
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error getting usage stats: {str(e)}")
        return jsonify({"error": f"Failed to get usage stats: {str(e)}"}), 500

# --- API Information ---

@api_v1.route('/', methods=['GET'])
def api_info():
    """Get API information"""
    logger.info("API info requested")
    return jsonify({
        "name": "API",
        "version": "1.0.0",
        "prefix": "/api/v1",
        "documentation": f"https://{domain_name}/docs",
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app = create_app()

    # Create SSL context
    ssl_context = (cert_path, key_path)

    logger.info(f"Running standalone API on port {port}")

    # Run with SSL
    app.run(host='0.0.0.0', port=port, ssl_context=ssl_context)

