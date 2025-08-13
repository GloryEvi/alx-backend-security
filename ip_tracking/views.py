

# Create your views here.

from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from .models import RequestLog
import json

def test_view(request):
    """Simple test view to verify middleware is working"""
    recent_logs = RequestLog.objects.all()[:10]
    return JsonResponse({
        'message': 'IP Tracking Middleware is working!',
        'your_ip': request.META.get('REMOTE_ADDR', 'unknown'),
        'path': request.path,
        'method': request.method,
        'recent_requests_count': RequestLog.objects.count(),
    })

def logs_view(request):
    """View to display recent request logs"""
    logs = RequestLog.objects.all()[:50]  # Last 50 requests
    return render(request, 'ip_tracking/logs.html', {'logs': logs})

@csrf_exempt
@require_http_methods(["POST"])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', block=True, group='anonymous')
def login_view(request):
    """Sensitive login view with rate limiting"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({'error': 'Username and password required'}, status=400)
        
        # Apply different rate limits based on authentication status
        if request.user.is_authenticated:
            # Already authenticated users get 10 requests/minute
            pass
        else:
            # Anonymous users get 5 requests/minute - handled by decorator above
            pass
        
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return JsonResponse({'success': True, 'message': 'Login successful'})
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error'}, status=500)
