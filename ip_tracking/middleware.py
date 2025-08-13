import logging
import requests
from django.utils.timezone import now
from django.http import HttpResponseForbidden
from django.core.cache import cache
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
        
        # Get geolocation data with caching
        country, city = self.get_geolocation(ip_address)
        
        # Log the request details
        location_info = f"{city}, {country}" if city and country else country or "Unknown"
        logger.info(
            f"Incoming request - IP: {ip_address}, "
            f"Location: {location_info}, "
            f"Path: {path}, "
            f"Method: {request.method}, "
            f"Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        
        # Save to database
        try:
            request_log = RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timestamp,
                path=path,
                country=country,
                city=city
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
    
    def get_geolocation(self, ip_address):
        """
        Get geolocation data for an IP address with 24-hour caching.
        
        Args:
            ip_address: The IP address to geolocate
            
        Returns:
            tuple: (country, city) or (None, None) if not found
        """
        # Skip geolocation for local/unknown IPs
        if ip_address in ['127.0.0.1', 'localhost', 'unknown'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return None, None
        
        # Check cache first
        cache_key = f"geo_{ip_address}"
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        try:
            # Using free ip-api.com service
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('country')
                    city = data.get('city')
                    
                    result = (country, city)
                    # Cache for 24 hours (86400 seconds)
                    cache.set(cache_key, result, 86400)
                    
                    return result
            
        except Exception as e:
            logger.error(f"Failed to get geolocation for IP {ip_address}: {str(e)}")
        
        # Cache empty result for 1 hour to avoid repeated API calls
        cache.set(cache_key, (None, None), 3600)
        return None, None