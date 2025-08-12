import logging
from django.utils.timezone import now
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

# Configure logging
logger = logging.getLogger('ip_tracking')

class IPTrackingMiddleware:
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    
    This middleware will:
    1. Extract the client's IP address (handling proxy forwarding)
    2. Record the timestamp of the request
    3. Capture the request path
    4. Save the information to the database
    5. Log the request details
    """
    
    def __init__(self, get_response):
        """
        Initialize the middleware.
        
        Args:
            get_response: The next middleware or view in the chain
        """
        self.get_response = get_response
        
        # One-time configuration and initialization
        logger.info("IPTrackingMiddleware initialized")
    
    def __call__(self, request):
        """
        Process each incoming request.
        
        Args:
            request: The Django request object
            
        Returns:
            The response from the next middleware/view or 403 Forbidden
        """
        # Get client IP address (handles proxy forwarding)
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            logger.warning(f"Blocked request from IP: {ip_address}, Path: {request.path}")
            return HttpResponseForbidden("Access Denied")
        
        # Get current timestamp
        timestamp = now()
        
        # Get request path
        path = request.path
        
        # Log the request details
        logger.info(
            f"Incoming request - IP: {ip_address}, "
            f"Path: {path}, "
            f"Method: {request.method}, "
            f"Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        # Save to database
        try:
            request_log = RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timestamp,
                path=path
            )
            logger.debug(f"Request logged with ID: {request_log.id}")
            
        except Exception as e:
            logger.error(f"Failed to save request log: {str(e)}")
        
        # Process the request through the rest of the middleware chain
        response = self.get_response(request)
        
        return response
    
    def get_client_ip(self, request):
        """
        Extract the client's IP address from the request.
        
        This method handles cases where the request comes through a proxy
        or load balancer by checking various headers in order of preference.
        
        Args:
            request: The Django request object
            
        Returns:
            str: The client's IP address or 'unknown' if not found
        """
        # Headers to check for the real IP address (in order of preference)
        ip_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR',
        ]
        
        for header in ip_headers:
            ip_list = request.META.get(header)
            if ip_list:
                # X-Forwarded-For can contain multiple IPs separated by commas
                # The first IP is usually the original client IP
                ip = ip_list.split(',')[0].strip()
                if ip and ip.lower() != 'unknown':
                    return ip
        
        # Fallback to unknown if no IP found
        return 'unknown'