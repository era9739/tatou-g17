import logging
import json
from datetime import datetime
from functools import wraps
from flask import request, g
import hashlib

# Configure structured logging
class SecurityLogger:
    def __init__(self, name='tatou_security'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # File handler for security events
        handler = logging.FileHandler('/var/log/tatou/security.log')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
    
    def log_event(self, event_type, **kwargs):
        """Log security event with structured data"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'ip_address': request.remote_addr if request else 'N/A',
            'user_agent': request.headers.get('User-Agent', 'N/A') if request else 'N/A',
            'user_id': getattr(g, 'user_id', None),
            **kwargs
        }
        self.logger.info(json.dumps(event))
        return event

security_logger = SecurityLogger()

# Decorator for logging API calls
def log_api_call(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        security_logger.log_event(
            'api_call',
            endpoint=request.endpoint,
            method=request.method,
            path=request.path
        )
        return func(*args, **kwargs)
    return wrapper

# Authentication events
def log_login_attempt(email, success, reason=None):
    security_logger.log_event(
        'login_attempt',
        email=email,
        success=success,
        reason=reason
    )

def log_login_success(user_id, email):
    security_logger.log_event(
        'login_success',
        user_id=user_id,
        email=email
    )

def log_login_failure(email, reason):
    security_logger.log_event(
        'login_failure',
        email=email,
        reason=reason
    )

# Document operations
def log_document_access(user_id, document_id, operation):
    security_logger.log_event(
        'document_access',
        user_id=user_id,
        document_id=document_id,
        operation=operation
    )

def log_unauthorized_access(user_id, resource, reason):
    security_logger.log_event(
        'unauthorized_access',
        user_id=user_id,
        resource=resource,
        reason=reason,
        severity='HIGH'
    )

# Suspicious activity
def log_suspicious_activity(activity_type, details):
    security_logger.log_event(
        'suspicious_activity',
        activity_type=activity_type,
        details=details,
        severity='CRITICAL'
    )

# Rate limiting events
def log_rate_limit_exceeded(endpoint):
    security_logger.log_event(
        'rate_limit_exceeded',
        endpoint=endpoint,
        severity='MEDIUM'
    )