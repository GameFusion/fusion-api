import os
import logging
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import uuid
from dotenv import load_dotenv
import requests
import slack_message

# Configure logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            database=os.getenv('DB_NAME', 'zeus_customs'),
            user=os.getenv('DB_USER', 'postgres'),
            password=os.getenv('DB_PASSWORD', 'postgres'),
            port=os.getenv('DB_PORT', '5432')
        )
        conn.autocommit = True
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def get_ip_location(ip_address):
    """Get location information from IP address using ip-api.com (free tier)"""
    try:
        if ip_address in ('127.0.0.1', 'localhost', '::1'):
            return {
                'country': 'Local',
                'regionName': 'Development',
                'city': 'Local',
                'latitude': 0,
                'longitude': 0
            }
            
        # Use ip-api.com free tier (no API key needed)
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
        return None
    except Exception as e:
        logger.error(f"Error getting IP location: {str(e)}")
        return None

def get_client_ip(request):
    """Get the client's real IP address, accounting for proxies"""
    # Check X-Forwarded-For header first (standard for proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # The leftmost IP is typically the original client
        return forwarded_for.split(',')[0].strip()
    
    # Check other common proxy headers
    for header in ['X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP']:
        if header in request.headers:
            return request.headers[header]
    
    # Fall back to remote_addr if no proxy headers are found
    return request.remote_addr

def log_api_usage(endpoint, user_id=None, request=None, success=None, message=None):
    """Log individual API usage to the database"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get IP address and user agent
        #ip_address = request.remote_addr if request else None
        ip_address = get_client_ip(request) if request else None
        user_agent = request.headers.get('User-Agent', '') if request else None
        
        # Get location data if IP address is available
        location_data = {}
        if ip_address:
            location = get_ip_location(ip_address)
            if location:
                location_data = {
                    'country': location.get('country'),
                    'region': location.get('region'),
                    'city': location.get('city'),
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude')
                }
        
        # Insert a new record for each API call - no aggregation
        cur.execute(
            """
            INSERT INTO api_usage 
            (user_id, endpoint, date, timestamp, ip_address, user_agent, country, region, city, 
             latitude, longitude, success, message)
            VALUES (%s, %s, CURRENT_DATE, CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (user_id, endpoint, ip_address, user_agent,
             location_data.get('country'), 
             location_data.get('region'), 
             location_data.get('city'),
             location_data.get('latitude'),
             location_data.get('longitude'),
             success, message)
        )
        
        # Close cursor and connection
        cur.close()
        conn.close()

        #country = location_data.get('country')
        #city = location_data.get('city')
        #message = f"api usage {endpoint} {country} {city} ip {ip_address} user id {user_id} agent {user_agent}"

        #slack_message.post("#general", message)

        return True
    except Exception as e:
        logger.error(f"Error logging API usage: {str(e)}")
        return False

def log_lookup(user_id, lookup_type, house_bill=None, voc_scac=None, master_bill=None, 
               status='success', error_message=None, request=None, batch_id=None, 
               batch_size=None, batch_index=None):
    """
    Log a lookup to the database, supporting both individual and batch lookups
    
    Args:
        user_id: User ID performing the lookup
        lookup_type: Type of lookup ('single' or 'batch')
        house_bill: House bill number (can be None for batch summary records)
        voc_scac: VOC SCAC code (can be None for batch summary records)
        master_bill: Master bill number if successful (can be None)
        status: 'success' or 'error'
        error_message: Error message if applicable
        request: Flask request object for IP and user agent info
        batch_id: UUID for the batch (to link related lookups)
        batch_size: Total size of the batch
        batch_index: Index of this lookup within the batch
    """
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get client IP and user agent
        #ip_address = request.remote_addr if request else None
        ip_address = get_client_ip(request) if request else None
        user_agent = request.headers.get('User-Agent', '') if request else None
        
        # Get location data if IP address is available
        location_data = {}
        if ip_address:
            location = get_ip_location(ip_address)
            if location:
                location_data = {
                    'country': location.get('country'),
                    'region': location.get('region'),
                    'city': location.get('city'),
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude')
                }
        
        # Insert lookup log with location data and batch info
        cur.execute(
            """
            INSERT INTO lookup_logs 
            (user_id, lookup_type, house_bill, voc_scac, master_bill, status, error_message, 
             ip_address, user_agent, country, region, city, latitude, longitude,
             batch_id, batch_size, batch_index)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, lookup_type, house_bill, voc_scac, master_bill, status, error_message, 
             ip_address, user_agent, 
             location_data.get('country'), 
             location_data.get('region'), 
             location_data.get('city'),
             location_data.get('latitude'),
             location_data.get('longitude'),
             batch_id, batch_size, batch_index)
        )
        
        # If successful, update the mapping table
        if status == 'success' and master_bill and house_bill and voc_scac:
            cur.execute(
                """
                INSERT INTO hbl_mbl_mappings (house_bill, voc_scac, master_bill)
                VALUES (%s, %s, %s)
                ON CONFLICT (house_bill, voc_scac) 
                DO UPDATE SET 
                    master_bill = EXCLUDED.master_bill,
                    last_lookup_at = CURRENT_TIMESTAMP,
                    lookup_count = hbl_mbl_mappings.lookup_count + 1
                """,
                (house_bill, voc_scac, master_bill)
            )
        
        # Commit changes
        conn.commit()
        
        # Close cursor and connection
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error logging lookup: {str(e)}")
        return False

def create_token_record(user_id, jti, expires_at, request=None):
    """Create a token record in the database with location data"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get IP address and user agent
        #ip_address = request.remote_addr if request else None
        ip_address = get_client_ip(request) if request else None
        user_agent = request.headers.get('User-Agent', '') if request else None
        
        # Get location data if IP address is available
        location_data = {}
        if ip_address:
            location = get_ip_location(ip_address)
            if location:
                location_data = {
                    'country': location.get('country'),
                    'region': location.get('region'),
                    'city': location.get('city'),
                    'latitude': location.get('latitude'),  # Note the column name difference
                    'longitude': location.get('longitude')  # Note the column name difference
                }
        
        # Insert token record with location data
        cur.execute(
            """
            INSERT INTO access_tokens 
            (user_id, token_id, expires_at, ip_address, user_agent, 
             country, region, city, latitude, longitude)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_id, jti, expires_at, ip_address, user_agent,
             location_data.get('country'), 
             location_data.get('region'), 
             location_data.get('city'),
             location_data.get('latitude'),
             location_data.get('longitude'))
        )
        
        # Close cursor and connection
        cur.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error creating token record: {str(e)}")
        return False

def is_token_revoked(jti):
    """Check if a token has been revoked"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if token is revoked
        cur.execute(
            """
            SELECT is_revoked FROM access_tokens 
            WHERE token_id = %s
            """,
            (jti,)
        )
        
        result = cur.fetchone()
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        if result and result[0]:
            return True
        return False
    except Exception as e:
        logger.error(f"Error checking token revocation: {str(e)}")
        # Fail-closed: If there's an error, treat the token as revoked for security
        return True

def get_user_by_username(username):
    """Get user information by username"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get user from database
        cur.execute(
            """
            SELECT id, username, password_hash, role, active 
            FROM users 
            WHERE username = %s
            """, 
            (username,)
        )
        
        user = cur.fetchone()
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return user
    except Exception as e:
        logger.error(f"Error getting user by username: {str(e)}")
        return None

def revoke_token_by_id(token_id):
    """Revoke a token by its ID"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Revoke the token
        cur.execute(
            """
            UPDATE access_tokens 
            SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
            WHERE token_id = %s
            """,
            (token_id,)
        )
        
        # Check if any rows were affected
        rows_affected = cur.rowcount
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return rows_affected > 0
    except Exception as e:
        logger.error(f"Error revoking token: {str(e)}")
        return False

def get_all_tokens():
    """Get all tokens with user information and location data"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get all tokens with location data
        cur.execute(
            """
            SELECT t.id, t.user_id, u.username, t.token_id, t.is_revoked, 
                   t.created_at, t.expires_at, t.revoked_at,
                   t.ip_address, t.user_agent, t.country, t.region, t.city, 
                   t.latitude, t.longitude
            FROM access_tokens t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
            """
        )
        
        tokens = cur.fetchall()
        
        # Convert timestamps to strings
        for token in tokens:
            token['created_at'] = token['created_at'].isoformat() if token['created_at'] else None
            token['expires_at'] = token['expires_at'].isoformat() if token['expires_at'] else None
            token['revoked_at'] = token['revoked_at'].isoformat() if token['revoked_at'] else None
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return tokens
    except Exception as e:
        logger.error(f"Error getting tokens: {str(e)}")
        return None

def get_all_users():
    """Get all users"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get all users
        cur.execute(
            """
            SELECT id, username, email, role, api_quota, active, created_at, updated_at
            FROM users
            ORDER BY username
            """
        )
        
        users = cur.fetchall()
        
        # Convert timestamps to strings
        for user in users:
            user['created_at'] = user['created_at'].isoformat() if user['created_at'] else None
            user['updated_at'] = user['updated_at'].isoformat() if user['updated_at'] else None
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return users
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return None

def get_usage_statistics():
    """Get API usage statistics with location data"""
    try:
        # Connect to the database
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get usage stats by endpoint with location data
        cur.execute(
            """
            SELECT u.username, a.endpoint, COUNT(*) as request_count,
                   a.country, a.region, a.city, a.latitude, a.longitude
            FROM api_usage a
            LEFT JOIN users u ON a.user_id = u.id
            GROUP BY u.username, a.endpoint, a.country, a.region, a.city, a.latitude, a.longitude
            ORDER BY u.username, a.endpoint
            """
        )
        
        results = cur.fetchall()
        
        # Organize results by user
        stats = {}
        for row in results:
            username = row['username'] or 'anonymous'  # Handle unauthenticated requests
            if username not in stats:
                stats[username] = {
                    "total_requests": 0,
                    "endpoints": {},
                    "locations": {}
                }
            
            # Add endpoint stats
            endpoint = row['endpoint']
            if endpoint not in stats[username]["endpoints"]:
                stats[username]["endpoints"][endpoint] = 0
            stats[username]["endpoints"][endpoint] += row['request_count']
            
            # Add location stats
            location_key = f"{row.get('country', 'Unknown')}/{row.get('city', 'Unknown')}"
            if location_key not in stats[username]["locations"]:
                stats[username]["locations"][location_key] = {
                    "count": 0,
                    "country": row.get('country'),
                    "region": row.get('region'),
                    "city": row.get('city'),
                    "coordinates": [row.get('longitude'), row.get('latitude')] if row.get('latitude') and row.get('longitude') else None
                }
            stats[username]["locations"][location_key]["count"] += row['request_count']
            
            stats[username]["total_requests"] += row['request_count']
        
        # Get lookup stats with location data
        cur.execute(
            """
            SELECT u.username, COUNT(*) as lookup_count, 
                   COUNT(*) FILTER (WHERE l.status = 'success') as success_count,
                   COUNT(*) FILTER (WHERE l.status = 'error') as error_count,
                   l.country, l.region, l.city, l.latitude, l.longitude,
                   COUNT(*) as location_count
            FROM lookup_logs l
            LEFT JOIN users u ON l.user_id = u.id
            GROUP BY u.username, l.country, l.region, l.city, l.latitude, l.longitude
            ORDER BY lookup_count DESC
            """
        )
        
        lookup_stats = cur.fetchall()
        
        # Get geographic distribution
        cur.execute(
            """
            SELECT country, COUNT(*) as country_count
            FROM api_usage
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY country_count DESC
            """
        )
        
        country_stats = cur.fetchall()
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return {
            "user_stats": stats,
            "lookup_stats": lookup_stats,
            "country_stats": country_stats,
            "period": "all time"
        }
    except Exception as e:
        logger.error(f"Error getting usage stats: {str(e)}")
        return None

def get_cached_master_bill(house_bill, voc_scac):
    """Get cached master bill from database if available"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute(
            """
            SELECT master_bill, last_lookup_at, lookup_count 
            FROM hbl_mbl_mappings 
            WHERE house_bill = %s AND voc_scac = %s
            """, 
            (house_bill, voc_scac)
        )
        
        result = cur.fetchone()
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
        return result
    except Exception as e:
        logger.error(f"Error getting cached master bill: {str(e)}")
        return None

def get_user_by_api_key(api_key):
    """Get user by API key"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, username, password_hash, email, role, active FROM users WHERE api_key = %s",
                    (api_key,)
                )
                user = cur.fetchone()
                if user:
                    return {
                        'id': user[0],
                        'username': user[1],
                        'password_hash': user[2],
                        'email': user[3],
                        'role': user[4],
                        'active': user[5]
                    }
                return None
    except Exception as e:
        logger.error(f"Database error when getting user by API key: {str(e)}")
        return None