"""
Secure Environment Configuration Manager
=========================================

Provides safe configuration validation, loading, and integrity checking.
Prevents common misconfigurations and detects placeholder values.
"""

import os
import hmac
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Validates environment configuration for security and completeness."""
    
    # Placeholder patterns that should not be used in production
    PLACEHOLDER_PATTERNS = [
        'your_',
        'change_this',
        'example',
        'default_',
        'todo',
        'xxx',
        'replace_',
        'secret_key_here',
        'app_password',
        'test_',
    ]
    
    # Required environment variables
    REQUIRED_VARS = {
        'SECRET_KEY': 'Flask session secret (auto-generated if not set)',
        'DATABASE_URL': 'Database connection URI',
        'SMTP_SERVER': 'Email SMTP server address (optional)',
    }
    
    # Recommended minimum lengths
    MIN_LENGTHS = {
        'SECRET_KEY': 32,  # At least 32 chars for cryptographic strength
        'PASSWORD': 12,    # For email/database passwords
    }
    
    @staticmethod
    def is_placeholder(value: str) -> bool:
        """Check if value appears to be a placeholder."""
        if not value or value == '':
            return True
        
        value_lower = value.lower()
        return any(pattern in value_lower for pattern in ConfigValidator.PLACEHOLDER_PATTERNS)
    
    @staticmethod
    def validate_secret_key(key: str) -> Tuple[bool, str]:
        """
        Validate SECRET_KEY strength.
        Returns: (is_valid, warning_message)
        """
        warnings = []
        
        if not key or key == '':
            return False, "SECRET_KEY is empty"
        
        if ConfigValidator.is_placeholder(key):
            warnings.append(f"⚠️  SECRET_KEY appears to be a placeholder ('{key}'). Change this in production!")
        
        if len(key) < ConfigValidator.MIN_LENGTHS['SECRET_KEY']:
            warnings.append(f"⚠️  SECRET_KEY is too short ({len(key)} chars). Minimum {ConfigValidator.MIN_LENGTHS['SECRET_KEY']} chars recommended.")
        
        # Check for weak patterns
        if key.count(key[0]) == len(key):  # All same character
            warnings.append("⚠️  SECRET_KEY has weak entropy (all same character).")
        
        return len(warnings) == 0, " ".join(warnings) if warnings else "OK"
    
    @staticmethod
    def validate_database_url(url: str) -> Tuple[bool, str]:
        """Validate DATABASE_URL format."""
        if not url or url == '':
            return False, "DATABASE_URL is empty. Using SQLite default."
        
        valid_schemes = ['sqlite', 'postgresql', 'mysql', 'mariadb']
        scheme = url.split('://')[0].lower() if '://' in url else None
        
        if scheme and scheme not in valid_schemes:
            return False, f"Unknown database scheme: {scheme}"
        
        return True, "OK"
    
    @staticmethod
    def validate_smtp_config(smtp_server: str, smtp_port: str, username: str, password: str) -> Tuple[bool, str]:
        """Validate SMTP email configuration."""
        warnings = []
        
        # SMTP is optional for development
        if not smtp_server or smtp_server == '':
            return True, "SMTP not configured (development mode - codes printed to console)"
        
        if username and ConfigValidator.is_placeholder(username):
            warnings.append("⚠️  SMTP_USERNAME appears to be a placeholder")
        
        if password and ConfigValidator.is_placeholder(password):
            warnings.append("⚠️  SMTP_PASSWORD appears to be a placeholder")
        
        try:
            port = int(smtp_port)
            if port not in [25, 465, 587, 2525]:  # Common SMTP ports
                warnings.append(f"⚠️  Unusual SMTP port: {port}")
        except (ValueError, TypeError):
            return False, "SMTP_PORT must be a valid port number"
        
        return len(warnings) == 0, " ".join(warnings) if warnings else "OK"


class ConfigIntegrityChecker:
    """Ensures .env files haven't been tampered with."""
    
    def __init__(self, secret: Optional[str] = None):
        """
        Initialize integrity checker.
        
        Args:
            secret: Signing secret (uses SECRET_KEY from env if not provided)
        """
        self.secret = secret or os.environ.get('SECRET_KEY', 'default-insecure-secret')
        self.signature_file = '.env.sig'
    
    def compute_signature(self, filepath: str) -> str:
        """Compute HMAC-SHA256 signature of a file."""
        try:
            with open(filepath, 'rb') as f:
                file_content = f.read()
            
            signature = hmac.new(
                self.secret.encode(),
                file_content,
                hashlib.sha256
            ).hexdigest()
            return signature
        except FileNotFoundError:
            return None
    
    def save_signature(self, filepath: str) -> bool:
        """Save signature for a config file."""
        try:
            signature = self.compute_signature(filepath)
            if signature:
                sig_path = filepath + '.sig'
                with open(sig_path, 'w') as f:
                    f.write(signature)
                logger.info(f"Config signature saved: {sig_path}")
                return True
        except Exception as e:
            logger.error(f"Error saving config signature: {e}")
        return False
    
    def verify_integrity(self, filepath: str) -> Tuple[bool, str]:
        """
        Verify .env file hasn't been tampered with.
        Returns: (is_valid, status_message)
        """
        sig_path = filepath + '.sig'
        
        if not Path(sig_path).exists():
            return True, "No signature file (first run or unsigned config)"
        
        try:
            with open(sig_path, 'r') as f:
                stored_signature = f.read().strip()
            
            current_signature = self.compute_signature(filepath)
            
            if current_signature != stored_signature:
                logger.warning(f"Config integrity check failed for {filepath}")
                return False, "⚠️  Config file appears to have been modified!"
            
            return True, "Config integrity verified"
        except Exception as e:
            logger.error(f"Error verifying config integrity: {e}")
            return False, f"Error checking integrity: {e}"


class EnvironmentManager:
    """Centralized environment variable management with validation."""
    
    def __init__(self):
        self.config = {}
        self.warnings = []
        self.errors = []
        self.loaded_at = None
    
    def load_and_validate(self) -> bool:
        """
        Load and validate all environment variables.
        Returns: True if all critical checks pass, False otherwise.
        """
        self.loaded_at = datetime.now()
        validator = ConfigValidator()
        
        # Check SECRET_KEY
        secret_key = os.environ.get('SECRET_KEY', '')
        is_valid, msg = validator.validate_secret_key(secret_key)
        if not is_valid:
            self.errors.append(f"SECRET_KEY: {msg}")
        elif msg != "OK":
            self.warnings.append(f"SECRET_KEY: {msg}")
        
        # Check DATABASE_URL
        db_url = os.environ.get('DATABASE_URL', 'sqlite:///auth.db')
        is_valid, msg = validator.validate_database_url(db_url)
        if not is_valid:
            self.warnings.append(f"DATABASE_URL: {msg}")
        
        # Check SMTP configuration
        smtp_server = os.environ.get('SMTP_SERVER', '')
        smtp_port = os.environ.get('SMTP_PORT', '587')
        smtp_user = os.environ.get('SMTP_USERNAME', '')
        smtp_pass = os.environ.get('SMTP_PASSWORD', '')
        
        is_valid, msg = validator.validate_smtp_config(smtp_server, smtp_port, smtp_user, smtp_pass)
        if not is_valid:
            self.errors.append(f"SMTP: {msg}")
        elif msg != "OK":
            self.warnings.append(f"SMTP: {msg}")
        
        # Log configuration audit
        self._log_config_audit()
        
        # Print warnings and errors
        self._report_issues()
        
        return len(self.errors) == 0
    
    def _log_config_audit(self):
        """Create audit log entry for configuration check."""
        audit_log = Path('logs/config_audit.log')
        audit_log.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(audit_log, 'a') as f:
                f.write(f"\n[{self.loaded_at.isoformat()}] Config validation\n")
                if self.warnings:
                    f.write(f"Warnings: {len(self.warnings)}\n")
                    for w in self.warnings:
                        f.write(f"  - {w}\n")
                if self.errors:
                    f.write(f"Errors: {len(self.errors)}\n")
                    for e in self.errors:
                        f.write(f"  - {e}\n")
                if not self.warnings and not self.errors:
                    f.write("Status: All checks passed\n")
        except Exception as e:
            logger.error(f"Could not write config audit log: {e}")
    
    def _report_issues(self):
        """Print configuration issues to console and logs."""
        if self.errors or self.warnings:
            print("\n" + "="*60)
            print("⚙️  CONFIGURATION REPORT")
            print("="*60)
            
            if self.warnings:
                print(f"\n⚠️  Warnings ({len(self.warnings)}):")
                for warning in self.warnings:
                    print(f"   {warning}")
            
            if self.errors:
                print(f"\n❌ Critical Issues ({len(self.errors)}):")
                for error in self.errors:
                    print(f"   {error}")
                print("\n⚠️  Fix these issues before running in production!")
            
            print("="*60 + "\n")
    
    def get_status(self) -> Dict:
        """Get configuration status for admin dashboard."""
        return {
            'loaded_at': self.loaded_at.isoformat() if self.loaded_at else None,
            'warnings_count': len(self.warnings),
            'errors_count': len(self.errors),
            'is_production_ready': len(self.errors) == 0 and len(self.warnings) == 0,
            'warnings': self.warnings,
            'errors': self.errors
        }


# Global instance
_env_manager = None

def get_environment_manager() -> EnvironmentManager:
    """Get or create the global environment manager."""
    global _env_manager
    if _env_manager is None:
        _env_manager = EnvironmentManager()
        _env_manager.load_and_validate()
    return _env_manager
