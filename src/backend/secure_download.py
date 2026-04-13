"""
DevPulse - Secure File Download
Path traversal protection and secure file serving
"""

import os
import logging
from pathlib import Path
from typing import Tuple, Optional
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# Define safe download directories
REPORTS_DIR = os.getenv("REPORTS_DIR", "/tmp/devpulse/reports")
EXPORTS_DIR = os.getenv("EXPORTS_DIR", "/tmp/devpulse/exports")

# Ensure directories exist
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(EXPORTS_DIR, exist_ok=True)


class SecureFileDownload:
    """Secure file download with path traversal protection"""
    
    ALLOWED_EXTENSIONS = {".pdf", ".json", ".csv", ".xlsx", ".txt"}
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

    @staticmethod
    def validate_path(filename: str, base_dir: str) -> Tuple[bool, Optional[Path], str]:
        """
        Validate file path to prevent path traversal attacks
        Returns: (is_valid, full_path, error_message)
        """
        try:
            # Reject if filename contains path separators or starts with /
            if "/" in filename or "\\" in filename or filename.startswith("."):
                return False, None, "Invalid filename"
            
            # Get the full path
            base_path = Path(base_dir).resolve()
            file_path = (base_path / filename).resolve()
            
            # SECURITY: Ensure the resolved path is still within base_dir
            if not str(file_path).startswith(str(base_path)):
                logger.warning(f"Path traversal attempt detected: {filename}")
                return False, None, "Access denied"
            
            # Check if file exists
            if not file_path.exists():
                return False, None, "File not found"
            
            # Check if it's a file (not directory)
            if not file_path.is_file():
                return False, None, "Not a file"
            
            # Check file extension
            if file_path.suffix.lower() not in SecureFileDownload.ALLOWED_EXTENSIONS:
                return False, None, "File type not allowed"
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > SecureFileDownload.MAX_FILE_SIZE:
                return False, None, "File too large"
            
            return True, file_path, ""
        
        except Exception as e:
            logger.error(f"Path validation error: {str(e)}")
            return False, None, "Validation error"

    @staticmethod
    def get_report(filename: str) -> Tuple[bool, Optional[Path], str]:
        """Get report file with validation"""
        return SecureFileDownload.validate_path(filename, REPORTS_DIR)

    @staticmethod
    def get_export(filename: str) -> Tuple[bool, Optional[Path], str]:
        """Get export file with validation"""
        return SecureFileDownload.validate_path(filename, EXPORTS_DIR)

    @staticmethod
    def get_safe_filename(original_filename: str) -> str:
        """
        Generate a safe filename from user input
        Removes any potentially dangerous characters
        """
        import re
        
        # Remove any path separators and special characters
        safe_name = re.sub(r'[^\w\s.-]', '', original_filename)
        # Remove leading dots
        safe_name = safe_name.lstrip('.')
        # Limit length
        safe_name = safe_name[:255]
        
        return safe_name or "download"

    @staticmethod
    def save_file(content: bytes, filename: str, directory: str) -> Tuple[bool, str, Optional[str]]:
        """
        Save file securely
        Returns: (success, message, saved_filename)
        """
        try:
            # Sanitize filename
            safe_filename = SecureFileDownload.get_safe_filename(filename)
            
            # Add timestamp to prevent collisions
            import time
            timestamp = int(time.time())
            name, ext = os.path.splitext(safe_filename)
            final_filename = f"{name}_{timestamp}{ext}"
            
            # Ensure directory exists
            os.makedirs(directory, exist_ok=True)
            
            # Save file
            file_path = os.path.join(directory, final_filename)
            with open(file_path, 'wb') as f:
                f.write(content)
            
            logger.info(f"File saved: {final_filename}")
            return True, "File saved successfully", final_filename
        
        except Exception as e:
            logger.error(f"File save error: {str(e)}")
            return False, f"Save failed: {str(e)}", None

    @staticmethod
    def delete_file(filename: str, directory: str) -> Tuple[bool, str]:
        """
        Delete file securely
        Returns: (success, message)
        """
        try:
            is_valid, file_path, error = SecureFileDownload.validate_path(filename, directory)
            
            if not is_valid:
                return False, error
            
            os.remove(file_path)
            logger.info(f"File deleted: {filename}")
            return True, "File deleted successfully"
        
        except Exception as e:
            logger.error(f"File delete error: {str(e)}")
            return False, f"Delete failed: {str(e)}"

    @staticmethod
    def list_files(directory: str, user_id: Optional[str] = None) -> list:
        """
        List files in directory
        Optionally filter by user_id prefix
        """
        try:
            if not os.path.exists(directory):
                return []
            
            files = []
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                
                # Skip directories
                if not os.path.isfile(file_path):
                    continue
                
                # Filter by user_id if provided
                if user_id and not filename.startswith(user_id):
                    continue
                
                # Get file info
                stat = os.stat(file_path)
                files.append({
                    "filename": filename,
                    "size": stat.st_size,
                    "created": stat.st_ctime,
                    "modified": stat.st_mtime
                })
            
            return sorted(files, key=lambda x: x["modified"], reverse=True)
        
        except Exception as e:
            logger.error(f"List files error: {str(e)}")
            return []
