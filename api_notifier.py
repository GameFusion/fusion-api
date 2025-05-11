# api_notifier.py

import time
import threading
import schedule
import datetime
import slack_message
import logging
from datetime import timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("api_notifier")

class ApiNotifier:
    def __init__(self, db_connection_func, slack_channel="#cbp-api", notify_all=False):
        """
        Initialize the API notifier service
        
        Args:
            db_connection_func: Function that returns a database connection
            slack_channel: Slack channel for notifications
            notify_all: Whether to notify about all API calls (default: False)
        """
        self.get_db_connection = db_connection_func
        self.slack_channel = slack_channel
        self.notify_all = notify_all
        self.last_processed_id = self._get_last_processed_id()
        self.start_time = datetime.datetime.now()
        self.running = False
        
    def _get_last_processed_id(self):
        """Get the last processed API usage ID from tracking table"""
        try:
            conn = self.get_db_connection()
            cur = conn.cursor()
            
            # Create tracking table if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS notification_tracking (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(50) UNIQUE NOT NULL,
                    last_id INTEGER NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            # Get the last processed ID
            cur.execute("""
                SELECT last_id FROM notification_tracking WHERE name = 'api_usage'
            """)
            result = cur.fetchone()
            
            if not result:
                # Get the current maximum ID from api_usage
                cur.execute("SELECT COALESCE(MAX(id), 0) FROM api_usage")
                max_id = cur.fetchone()[0]
                
                # Insert initial tracking record
                cur.execute("""
                    INSERT INTO notification_tracking (name, last_id, updated_at)
                    VALUES ('api_usage', %s, CURRENT_TIMESTAMP)
                """, (max_id,))
                conn.commit()
                last_id = max_id
            else:
                last_id = result[0]
            
            cur.close()
            conn.close()
            
            return last_id
            
        except Exception as e:
            logger.error(f"Error getting last processed ID: {str(e)}")
            return 0
    
    def _update_last_processed_id(self, new_id):
        """Update the last processed ID in tracking table"""
        try:
            conn = self.get_db_connection()
            cur = conn.cursor()
            
            cur.execute("""
                UPDATE notification_tracking 
                SET last_id = %s, updated_at = CURRENT_TIMESTAMP
                WHERE name = 'api_usage'
            """, (new_id,))
            conn.commit()
            
            cur.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating last processed ID: {str(e)}")
    
    def _get_new_api_calls(self):
        """Get new API calls since last check"""
        try:
            conn = self.get_db_connection()
            cur = conn.cursor()
            
            cur.execute("""
                SELECT a.id, a.endpoint, a.timestamp, a.ip_address, 
                       a.country, a.city, a.user_id, u.username
                FROM api_usage a
                LEFT JOIN users u ON a.user_id = u.id
                WHERE a.id > %s
                ORDER BY a.id ASC
                LIMIT 100
            """, (self.last_processed_id,))
            
            new_calls = cur.fetchall()
            
            if new_calls:
                # Update last processed ID
                self.last_processed_id = new_calls[-1][0]
                self._update_last_processed_id(self.last_processed_id)
            
            cur.close()
            conn.close()
            
            return new_calls
            
        except Exception as e:
            logger.error(f"Error getting new API calls: {str(e)}")
            return []
    
    def _format_api_call_for_slack(self, api_call):
        """Format an API call for Slack notification"""
        id, endpoint, timestamp, ip, country, city, user_id, username = api_call
        
        # Format the endpoint in a more readable way
        endpoint_parts = endpoint.split('/')
        readable_endpoint = endpoint_parts[-1] if len(endpoint_parts) > 0 else endpoint
        
        # Format the location
        location = ""
        if city and country:
            location = f"{city}, {country}"
        elif country:
            location = country
        
        # Format the user
        user = username if username else f"User #{user_id}" if user_id else "Anonymous"
        
        # Format the timestamp
        timestamp_str = timestamp.strftime("%H:%M:%S")
        
        return f"{timestamp_str} | {readable_endpoint} | {user} | {location} | {ip}"
    
    def _send_api_call_notification(self, api_call):
        """Send a notification for a single API call"""
        formatted_message = self._format_api_call_for_slack(api_call)
        slack_message.post(self.slack_channel, formatted_message)
    
    def _get_api_usage_summary(self, hours=1):
        """Get API usage summary for the specified hours"""
        try:
            conn = self.get_db_connection()
            cur = conn.cursor()
            
            # Get total calls and unique statistics
            cur.execute("""
                SELECT COUNT(*) as total_calls, 
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(DISTINCT endpoint) as unique_endpoints
                FROM api_usage 
                WHERE timestamp > NOW() - INTERVAL '%s hours'
            """, (hours,))
            result = cur.fetchone()
            
            if not result or result[0] == 0:
                cur.close()
                conn.close()
                return f"📊 No API calls in the past {hours}h"
                    
            total_calls, unique_ips, unique_users, unique_endpoints = result
            
            # Get top endpoint
            cur.execute("""
                SELECT endpoint, COUNT(*) as count
                FROM api_usage 
                WHERE timestamp > NOW() - INTERVAL '%s hours'
                GROUP BY endpoint
                ORDER BY count DESC
                LIMIT 1
            """, (hours,))
            top_endpoint = cur.fetchone()
            
            # Close cursor and connection
            cur.close()
            conn.close()
            
            # Calculate uptime
            uptime = datetime.datetime.now() - self.start_time
            hours_up, remainder = divmod(uptime.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{int(hours_up)}h {int(minutes)}m"
            
            # Format the summary
            summary = (
                f"⏱️ Uptime: {uptime_str} | "
                f"📊 API: {total_calls:,} calls from {unique_ips:,} IPs and {unique_users:,} users in past {hours}h"
            )
            
            if top_endpoint:
                endpoint, count = top_endpoint
                endpoint_name = endpoint.split('/')[-1] if '/' in endpoint else endpoint
                percent = (count / total_calls) * 100
                summary += f" | Top: {endpoint_name} ({percent:.1f}%)"
            
            return summary
                
        except Exception as e:
            logger.error(f"Error getting API usage summary: {str(e)}")
            return f"📊 API stats unavailable: {str(e)}"
    
    def _send_hourly_summary(self):
        """Send hourly summary of API usage"""
        logger.info("Sending hourly API usage summary")
        summary = self._get_api_usage_summary(hours=1)
        daily_summary = self._get_api_usage_summary(hours=24)
        
        message = f"*Hourly Summary:* {summary}\n*24h Summary:* {daily_summary}"
        slack_message.post(self.slack_channel, message)
    
    def check_for_new_calls(self):
        """Check for new API calls and send notifications"""
        new_calls = self._get_new_api_calls()
        
        if not new_calls:
            return
            
        # If notify_all is True, send a notification for each call
        # Otherwise, just log the calls
        if self.notify_all:
            for call in new_calls:
                self._send_api_call_notification(call)
        else:
            print("notify all disabled", flush=True)
        
        logger.info(f"Processed {len(new_calls)} new API calls")
    
    def run(self):
        """Run the notifier service"""
        self.running = True
        logger.info(f"Starting API Notifier service, monitoring for new API calls. Last processed ID: {self.last_processed_id}")
        
        # Schedule the hourly summary
        schedule.every().hour.at(":00").do(self._send_hourly_summary)
        
        # Send initial summary
        self._send_hourly_summary()
        
        try:
            while self.running:
                schedule.run_pending()
                self.check_for_new_calls()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("API Notifier service stopped by user")
        except Exception as e:
            logger.error(f"Error in API Notifier service: {str(e)}")
            self.running = False
    
    def start(self):
        """Start the notifier service in a background thread"""
        thread = threading.Thread(target=self.run)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self):
        """Stop the notifier service"""
        self.running = False