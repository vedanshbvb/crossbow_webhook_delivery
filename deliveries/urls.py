from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SubscriptionViewSet, delivery_status, CustomAuthToken, RegisterView, ingest_webhook, delivery_attempt_history

router = DefaultRouter()
router.register(r'subscriptions', SubscriptionViewSet)
router.register(r'register', RegisterView, basename='register')

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/delivery-status/<int:delivery_id>/', delivery_status, name='delivery-status'),
    path('api/auth/token/', CustomAuthToken.as_view(), name='api_token_auth'),
    path('api/ingest/<str:subscription_id>/', ingest_webhook, name='ingest-webhook'),
    path('api/delivery-attempt-history/<int:delivery_id>/', delivery_attempt_history, name='delivery-attempt-history'),
]
