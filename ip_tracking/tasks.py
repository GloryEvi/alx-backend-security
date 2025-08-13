from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger('ip_tracking')

@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IP addresses based on:
    1. IPs exceeding 100 requests/hour
    2. IPs accessing sensitive paths (/admin, /login)
    
    Runs hourly to analyze request patterns.
    """
    logger.info("Starting suspicious IP detection task")
    
    # Get requests from the last hour
    one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
    recent_requests = RequestLog.objects.filter(timestamp__gte=one_hour_ago)
    
    # Define sensitive paths
    sensitive_paths = ['/admin', '/login', '/admin/', '/login/', '/api/login', '/api/admin']
    
    flagged_count = 0
    
    # 1. Flag IPs with more than 100 requests/hour
    high_volume_ips = (
        recent_requests
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        reason = f"High volume: {request_count} requests in the last hour"
        
        # Avoid duplicate flags
        if not SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__icontains="High volume",
            flagged_at__gte=one_hour_ago
        ).exists():
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )
            flagged_count += 1
            logger.warning(f"Flagged high-volume IP: {ip_address} ({request_count} requests)")
    
    # 2. Flag IPs accessing sensitive paths
    for sensitive_path in sensitive_paths:
        sensitive_requests = recent_requests.filter(path__icontains=sensitive_path)
        sensitive_ips = (
            sensitive_requests
            .values('ip_address')
            .annotate(access_count=Count('id'))
            .filter(access_count__gte=5)  # Flag if accessing sensitive paths 5+ times
        )
        
        for ip_data in sensitive_ips:
            ip_address = ip_data['ip_address']
            access_count = ip_data['access_count']
            
            reason = f"Sensitive path access: {access_count} attempts to {sensitive_path}"
            
            # Avoid duplicate flags
            if not SuspiciousIP.objects.filter(
                ip_address=ip_address,
                reason__icontains="Sensitive path access",
                flagged_at__gte=one_hour_ago
            ).exists():
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=reason
                )
                flagged_count += 1
                logger.warning(f"Flagged sensitive access IP: {ip_address} ({access_count} attempts to {sensitive_path})")
    
    # 3. Additional anomaly detection - rapid sequential requests
    rapid_request_ips = (
        recent_requests
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gte=50)  # 50+ requests in an hour
    )
    
    for ip_data in rapid_request_ips:
        ip_address = ip_data['ip_address']
        
        # Check if requests are too frequent (average < 2 minutes apart)
        ip_requests = recent_requests.filter(ip_address=ip_address).order_by('timestamp')
        if ip_requests.count() >= 50:
            time_span = (ip_requests.last().timestamp - ip_requests.first().timestamp).total_seconds()
            avg_interval = time_span / ip_requests.count()
            
            if avg_interval < 120:  # Less than 2 minutes average
                reason = f"Rapid requests: {ip_requests.count()} requests with {avg_interval:.1f}s average interval"
                
                if not SuspiciousIP.objects.filter(
                    ip_address=ip_address,
                    reason__icontains="Rapid requests",
                    flagged_at__gte=one_hour_ago
                ).exists():
                    SuspiciousIP.objects.create(
                        ip_address=ip_address,
                        reason=reason
                    )
                    flagged_count += 1
                    logger.warning(f"Flagged rapid requests IP: {ip_address} ({avg_interval:.1f}s interval)")
    
    logger.info(f"Suspicious IP detection completed. Flagged {flagged_count} new suspicious IPs")
    return f"Flagged {flagged_count} suspicious IPs"