from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from rest_framework.authtoken.views import obtain_auth_token
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView

router = DefaultRouter()
router.register(r'subscriptions', views.SubscriptionViewSet, basename='subscription')

urlpatterns = [
    # Web interface URLs
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('facilities/', views.facilities, name='facilities'),
    path('logout/', views.logout_view, name='logout'),
    path('logs/', views.logs_view, name='logs'),
    
    # API endpoints
    path('api/', include(router.urls)),  # For create_subscription
    path('api/ingest/<str:sub_id>/', views.ingest_webhook, name='ingest_webhook'),  # For send_payload
    path('api/delivery-status/<int:delivery_id>/', views.delivery_status, name='delivery_status'),  # For check_delivery_status
    path('api/delivery-attempt-history/<int:delivery_id>/', views.delivery_attempt_history, name='delivery_attempt_history'),
    path('api/subscription-attempt-history/<str:sub_id>/', views.subscription_attempt_history, name='subscription_attempt_history'),
]
