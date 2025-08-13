# ALX Backend Security - Complete IP Tracking & Security System

A comprehensive Django-based security monitoring system that implements IP tracking, geolocation, rate limiting, IP blocking, and anomaly detection for web applications.

## 🔥 Features

### 1. **IP Tracking Middleware**
- Logs every incoming request with IP address, timestamp, and path
- Handles proxy forwarding and real IP detection
- Database persistence with indexed fields for performance

### 2. **Geolocation Integration**
- Automatically detects country and city for each IP address
- Uses free ip-api.com service with 24-hour caching
- Handles local/private IP addresses gracefully

### 3. **IP Blocking System**
- Blacklist-based IP blocking with immediate 403 Forbidden response
- Django management command to easily block IPs
- Cached blocking checks for performance

### 4. **Rate Limiting**
- Configurable rate limits: 10 requests/minute (authenticated), 5 requests/minute (anonymous)
- Applied to sensitive endpoints like login
- Uses django-ratelimit with IP-based limiting

### 5. **Anomaly Detection**
- Automated Celery task running hourly
- Detects suspicious patterns:
  - High volume (100+ requests/hour)
  - Sensitive path access (/admin, /login)
  - Rapid sequential requests
- Automatic flagging of suspicious IPs

## 🏗️ Project Structure

```
alx-backend-security/
├── backend_security/                 # Main Django project
│   ├── settings.py                  # Configuration with middleware & rate limiting
│   ├── urls.py                      # Main URL routing
│   └── ...
├── ip_tracking/                     # Security monitoring app
│   ├── middleware.py                # IP tracking & blocking middleware
│   ├── models.py                    # RequestLog, BlockedIP, SuspiciousIP models
│   ├── tasks.py                     # Celery tasks for anomaly detection
│   ├── views.py                     # Rate-limited views (login, test)
│   ├── admin.py                     # Django admin configuration
│   ├── urls.py                      # App URL patterns
│   └── management/commands/
│       └── block_ip.py              # Command to block IPs
├── requirements.txt                 # Python dependencies
├── .gitignore                      # Git ignore rules
└── README.md                       # This comprehensive guide
```

## 🚀 Quick Start

### 1. **Clone & Setup**
```bash
git clone https://github.com/yourusername/alx-backend-security.git
cd alx-backend-security

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. **Database Setup**
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser  # Optional
```

### 3. **Run Development Server**
```bash
python manage.py runserver
```

### 4. **Set Up Celery (for anomaly detection)**
```bash
# Install Redis (required for Celery)
# Ubuntu: sudo apt-get install redis-server
# macOS: brew install redis

# Start Celery worker
celery -A backend_security worker --loglevel=info

# Start Celery beat (for scheduled tasks)
celery -A backend_security beat --loglevel=info
```

## 📊 Database Models

### RequestLog
```python
ip_address    # GenericIPAddressField - Client IP
timestamp     # DateTimeField - Request time  
path          # CharField - URL path requested
country       # CharField - Geolocation country
city          # CharField - Geolocation city
```

### BlockedIP
```python
ip_address    # GenericIPAddressField - Blocked IP (unique)
```

### SuspiciousIP
```python
ip_address    # GenericIPAddressField - Flagged IP
reason        # CharField - Why it was flagged
flagged_at    # DateTimeField - When it was flagged
```

## 🔧 Configuration

### Settings.py Key Configurations
```python
# Middleware order (IP blocking before other middleware)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # ... other middleware ...
    'ip_tracking.middleware.IPTrackingMiddleware',  # Add this
]

# Rate limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Logging configuration for monitoring
LOGGING = {
    # ... logging config for ip_tracking ...
}
```

## 🛡️ Security Features in Detail

### IP Tracking Middleware
- **Proxy Detection**: Handles X-Forwarded-For, X-Real-IP headers
- **Performance**: Efficient database operations with proper indexing
- **Logging**: Comprehensive request logging to files and console

### Geolocation System
- **API Integration**: Uses ip-api.com free service
- **Caching**: 24-hour cache to reduce API calls
- **Local IP Handling**: Skips geolocation for private/local IPs
- **Error Handling**: Graceful fallback on API failures

### Rate Limiting Implementation
```python
@ratelimit(key='ip', rate='10/m', method='POST', block=True)  # Authenticated
@ratelimit(key='ip', rate='5/m', method='POST', block=True, group='anonymous')  # Anonymous
def login_view(request):
    # Rate-limited login endpoint
```

### Anomaly Detection Logic
- **High Volume**: Flags IPs with 100+ requests/hour
- **Sensitive Access**: Monitors /admin, /login path access
- **Rapid Requests**: Detects unusually fast request patterns
- **Duplicate Prevention**: Avoids flagging the same IP multiple times

## 🔨 Management Commands

### Block an IP Address
```bash
python manage.py block_ip 192.168.1.100
python manage.py block_ip 2001:db8::1
```

### Run Anomaly Detection Manually
```bash
python manage.py shell
>>> from ip_tracking.tasks import detect_suspicious_ips
>>> detect_suspicious_ips.delay()
```

## 📈 API Endpoints

| Endpoint | Method | Description | Rate Limited |
|----------|---------|-------------|--------------|
| `/` | GET | Home page with endpoint list | No |
| `/ip-tracking/test/` | GET | Test middleware functionality | No |
| `/ip-tracking/logs/` | GET | View recent request logs | No |
| `/ip-tracking/login/` | POST | Rate-limited login endpoint | ✅ Yes |
| `/admin/` | GET/POST | Django admin interface | Monitored |

## 🔍 Monitoring & Analytics

### View Request Logs
- **Admin Interface**: `/admin/` → Request Logs
- **API Endpoint**: `/ip-tracking/test/` shows request count
- **Log Files**: Check `ip_tracking.log` in project root

### Monitor Blocked IPs
- **Admin Interface**: View and manage blocked IPs
- **Command Line**: Use `block_ip` management command

### Suspicious IP Analysis
- **Admin Interface**: Review flagged suspicious IPs
- **Automated Detection**: Celery task runs hourly
- **Manual Trigger**: Run tasks via Django shell

## 🚦 Testing the System

### Test IP Tracking
```bash
curl http://127.0.0.1:8000/ip-tracking/test/
```

### Test Rate Limiting
```bash
# Rapid requests to trigger rate limiting
for i in {1..10}; do
  curl -X POST http://127.0.0.1:8000/ip-tracking/login/ \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}'
done
```

### Test IP Blocking
```bash
# Block your IP
python manage.py block_ip 127.0.0.1

# Try to access (should get 403 Forbidden)
curl http://127.0.0.1:8000/ip-tracking/test/
```

## 📦 Dependencies

```
Django>=4.2,<5.0      # Web framework
requests              # HTTP library for geolocation API
django-ratelimit      # Rate limiting functionality
celery               # Async task queue for anomaly detection
redis                # Message broker for Celery
```

## 🔒 Security Considerations

- **Rate Limiting**: Prevents brute force attacks
- **IP Blocking**: Immediate threat response
- **Geolocation**: Geographic threat analysis
- **Anomaly Detection**: Proactive threat identification
- **Logging**: Comprehensive audit trail
- **Caching**: Performance optimization without sacrificing security

## 🚀 Production Deployment

### Environment Variables
```bash
export DJANGO_SECRET_KEY="your-secret-key"
export DJANGO_DEBUG=False
export DJANGO_ALLOWED_HOSTS="yourdomain.com"
```

### Performance Optimizations
- Use Redis for caching and Celery broker
- Configure proper database indexes
- Set up log rotation for ip_tracking.log
- Monitor Celery task performance

### Security Hardening
- Enable HTTPS in production
- Configure proper CORS settings
- Set up database connection pooling
- Implement proper backup strategies

## 📊 Metrics & Monitoring

The system provides comprehensive metrics for security analysis:

- **Request Volume**: Track requests per IP over time
- **Geographic Distribution**: Analyze request origins
- **Blocked Requests**: Monitor blocking effectiveness  
- **Anomaly Trends**: Review suspicious activity patterns
- **Rate Limit Hits**: Identify potential attacks

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new functionality
5. Submit a pull request

## 📝 License

This project is part of the ALX Backend Security curriculum.

---

**Built with Django for robust backend security monitoring and threat detection.**