from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    path('test/', views.test_view, name='test'),
    path('logs/', views.logs_view, name='logs'),
    path('login/', views.login_view, name='login'),
]