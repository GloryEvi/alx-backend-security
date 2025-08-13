from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to store IP address, timestamp, and path of incoming requests.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        help_text="The IP address of the client making the request"
    )
    
    timestamp = models.DateTimeField(
        default=timezone.now,
        verbose_name="Timestamp",
        help_text="When the request was made"
    )
    
    path = models.CharField(
        max_length=500,
        verbose_name="Request Path",
        help_text="The URL path that was requested"
    )
    
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="Country",
        help_text="Country from geolocation"
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="City",
        help_text="City from geolocation"
    )
    
    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']  # Most recent first
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
    
    def __str__(self):
        location = ""
        if self.city and self.country:
            location = f" ({self.city}, {self.country})"
        elif self.country:
            location = f" ({self.country})"
        return f"{self.ip_address} - {self.path}{location} at {self.timestamp}"
    
    @property
    def formatted_timestamp(self):
        """Return a nicely formatted timestamp"""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        verbose_name="IP Address",
        help_text="The IP address to block"
    )
    
    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        indexes = [
            models.Index(fields=['ip_address']),
        ]
    
    def __str__(self):
        return self.ip_address


class SuspiciousIP(models.Model):
    """
    Model to store suspicious IP addresses flagged by anomaly detection.
    """
    ip_address = models.GenericIPAddressField(
        verbose_name="IP Address",
        help_text="The suspicious IP address"
    )
    
    reason = models.CharField(
        max_length=500,
        verbose_name="Reason",
        help_text="Reason why this IP was flagged as suspicious"
    )
    
    flagged_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Flagged At",
        help_text="When this IP was flagged"
    )
    
    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ['-flagged_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['flagged_at']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason}"