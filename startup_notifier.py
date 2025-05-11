import subprocess
import os
import socket
from datetime import datetime
import slack_message
from dotenv import load_dotenv

load_dotenv()

# Get domain name from environment variables with a default fallback
domain_name = os.environ.get('API_DOMAIN_NAME')

def get_git_info():
    """Get current git commit info and pending changes"""
    try:
        # Get current commit hash and date
        commit_hash = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], 
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        
        commit_date = subprocess.check_output(
            ["git", "log", "-1", "--format=%cd", "--date=iso"], 
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        
        # Get the commit message
        commit_message = subprocess.check_output(
            ["git", "log", "-1", "--pretty=%B"], 
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        
        # Check for modified files
        modified_files = subprocess.check_output(
            ["git", "ls-files", "--modified"], 
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        
        # Check for untracked files
        untracked_files = subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"], 
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        
        # Format the data
        info = {
            "commit_hash": commit_hash[:8],  # Short hash
            "full_commit_hash": commit_hash,
            "commit_date": commit_date,
            "commit_message": commit_message,
            "modified_files": modified_files.split('\n') if modified_files else [],
            "untracked_files": untracked_files.split('\n') if untracked_files else [],
            "has_pending_changes": bool(modified_files or untracked_files)
        }
        
        return info
    except Exception as e:
        return {
            "error": str(e),
            "commit_hash": "unknown",
            "commit_date": "unknown",
            "modified_files": [],
            "untracked_files": [],
            "has_pending_changes": False
        }

def get_server_info():
    """Get basic server information"""
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    python_version = subprocess.check_output(["python", "--version"]).decode('utf-8').strip()
    
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "python_version": python_version,
        "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

def send_startup_message():
    """Send enhanced startup message to Slack"""
    git_info = get_git_info()
    
    server_info = get_server_info()
    
    # Build message

    message = [
        f"🚀 *API Server online for {domain_name}*",
        f"*Server:* {server_info['hostname']} ({server_info['ip_address']})",
        f"*Started at:* {server_info['start_time']}",
        f"*Environment:* {os.environ.get('FLASK_ENV', 'production')}",
        f"*Python:* {server_info['python_version']}",
        f"\n*Git Commit:* `{git_info['commit_hash']}` - {git_info['commit_date']}"
    ]

    post_commit_details = False
    if post_commit_details:
        message.append(f"*Commit Message:* _{git_info['commit_message']}_")
    else:
        # Extract just the first line of the commit message
        commit_message = git_info['commit_message'].split('\n')[0]
        message.append(f"*Commit Message:* _{commit_message}_")

    # Add pending changes info if any
    if git_info['has_pending_changes']:
        message.append("\n⚠️ *WARNING: Uncommitted changes detected!*")
        
        if git_info['modified_files']:
            modified_files_str = "\n".join([f"  • {f}" for f in git_info['modified_files'][:5]])
            if len(git_info['modified_files']) > 5:
                modified_files_str += f"\n  • ... and {len(git_info['modified_files']) - 5} more"
            message.append(f"*Modified files:*\n```{modified_files_str}```")
        
        post_untracked_files = False
        if post_untracked_files:
            if git_info['untracked_files']:
                untracked_files_str = "\n".join([f"  • {f}" for f in git_info['untracked_files'][:5]])
                if len(git_info['untracked_files']) > 5:
                    untracked_files_str += f"\n  • ... and {len(git_info['untracked_files']) - 5} more"
                message.append(f"*Untracked files:*\n```{untracked_files_str}```")
    else:
        message.append("✅ *Clean working directory*")
    
    # Send the message to Slack
    slack_message.post("#general", "\n".join(message))

# Call this function when starting your service
if __name__ == "__main__":
    # If run directly, send to default channel
    send_startup_message()
