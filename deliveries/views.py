from django.shortcuts import render
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .models import Subscription, DeliveryLog
from .serializers import SubscriptionSerializer, DeliveryLogSerializer, UserSerializer
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta

class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })

class SubscriptionViewSet(viewsets.ModelViewSet):
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]
    queryset = Subscription.objects.all()

    def get_queryset(self):
        # Try to get from cache first
        cache_key = f'subscription_list_{self.request.user.id}'
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cached_data
        
        # If not in cache, get from DB and cache it
        queryset = Subscription.objects.filter(user=self.request.user)
        cache.set(cache_key, queryset, timeout=300)  # Cache for 5 minutes
        return queryset

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['get'])
    def recent_deliveries(self, request, pk=None):
        """Get recent delivery attempts for a subscription"""
        subscription = self.get_object()
        if subscription.user != request.user:
            return Response(
                {'error': 'Not authorized to view this subscription'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        recent_logs = DeliveryLog.objects.filter(
            subscription=subscription
        ).order_by('-timestamp')[:20]
        
        serializer = DeliveryLogSerializer(recent_logs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def delivery_stats(self, request, pk=None):
        """Get delivery statistics for a subscription"""
        subscription = self.get_object()
        if subscription.user != request.user:
            return Response(
                {'error': 'Not authorized to view this subscription'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        last_24h = timezone.now() - timedelta(hours=24)
        
        stats = {
            'total_attempts': DeliveryLog.objects.filter(subscription=subscription).count(),
            'successful_deliveries': DeliveryLog.objects.filter(
                subscription=subscription,
                status='Success'
            ).count(),
            'failed_deliveries': DeliveryLog.objects.filter(
                subscription=subscription,
                status='Failure'
            ).count(),
            'last_24h_attempts': DeliveryLog.objects.filter(
                subscription=subscription,
                timestamp__gte=last_24h
            ).count()
        }
        
        return Response(stats)

    def create(self, request, *args, **kwargs):
        # Implement logic for creating a subscription
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        # Implement logic for updating a subscription
        return super().update(request, *args, **kwargs)

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .tasks import process_webhook

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ingest_webhook(request, subscription_id):
    """Ingest a webhook for a specific subscription"""
    try:
        subscription = Subscription.objects.get(subscription_id=subscription_id)
        if subscription.user != request.user:
            return Response(
                {'error': 'Not authorized to use this subscription'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        # Create initial delivery log
        delivery_log = DeliveryLog.objects.create(
            subscription=subscription,
            attempt_number=1,
            status='Queued'
        )
            
        # Queue the webhook processing task
        process_webhook.apply_async(args=[subscription_id, request.data, delivery_log.id])
        return Response({
            'message': 'Webhook queued for processing',
            'delivery_id': delivery_log.id
        }, status=status.HTTP_202_ACCEPTED)
    except Subscription.DoesNotExist:
        return Response(
            {'error': 'Subscription not found'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def delivery_status(request, delivery_id):
    """Get status of a specific delivery attempt"""
    try:
        log = DeliveryLog.objects.get(id=delivery_id)
        if log.subscription.user != request.user:
            return Response(
                {'error': 'Not authorized to view this delivery log'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        serializer = DeliveryLogSerializer(log)
        return Response(serializer.data)
    except DeliveryLog.DoesNotExist:
        return Response(
            {'error': 'Delivery log not found'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def delivery_attempt_history(request, delivery_id):
    """Get all attempts (history) for a specific delivery task ID (delivery_id)"""
    try:
        log = DeliveryLog.objects.get(id=delivery_id)
        if log.subscription.user != request.user:
            return Response({'error': 'Not authorized to view this delivery log'}, status=403)
        # Find all logs for this subscription, ordered by timestamp, last 20
        logs = DeliveryLog.objects.filter(subscription=log.subscription).order_by('-timestamp')[:20]
        serializer = DeliveryLogSerializer(logs, many=True)
        return Response(serializer.data)
    except DeliveryLog.DoesNotExist:
        return Response({'error': 'Delivery log not found'}, status=404)

class RegisterView(viewsets.ViewSet):
    permission_classes = [AllowAny]
    
    def create(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = User.objects.create_user(
                username=serializer.validated_data['username'],
                email=serializer.validated_data['email'],
                password=request.data.get('password')
            )
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

