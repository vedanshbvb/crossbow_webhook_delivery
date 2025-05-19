from django.shortcuts import render, redirect
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from .models import Subscription, DeliveryLog
from .serializers import SubscriptionSerializer, DeliveryLogSerializer, UserSerializer
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import uuid
import hmac
import hashlib
import json
from django.conf import settings
from .tasks import process_webhook

def get_user_from_token(request):
    # auth_header = request.headers.get('Authorization')
    # if auth_header and auth_header.startswith('Token '):
    #     token_key = auth_header.split(' ')[1]
    #     try:
    #         token = Token.objects.get(key=token_key)
    #         return token.user
    #     except Token.DoesNotExist:
    #         return None
    # return None
    # Check Authorization header first
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if auth_header and auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        try:
            return Token.objects.get(key=token_key).user
        except Token.DoesNotExist:
            return None
    
    # Check for token in POST data (for form submissions)
    token_key = request.POST.get('token') or request.GET.get('token')
    if token_key:
        try:
            return Token.objects.get(key=token_key).user
        except Token.DoesNotExist:
            return None
    
    return None

def home(request):
    if request.user.is_authenticated:
        return redirect('facilities')
    return redirect('login')

@login_required
def facilities(request):
    context = {
        'user_id': request.user.id
    }
    return render(request, 'facilities.html', context)

def login_view(request):
    if request.user.is_authenticated:
        return redirect('facilities')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('facilities')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'login.html')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('facilities')
        
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'register.html')
            
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'register.html')
            
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'register.html')
            
        user = User.objects.create_user(username=username, email=email, password=password1)
        login(request, user)
        return redirect('facilities')
        
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_token(request):
    """Verify if the token is valid"""
    return Response({'status': 'valid'})

class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.id
        })

class SubscriptionViewSet(viewsets.ModelViewSet):
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]
    queryset = Subscription.objects.all()

    def get_queryset(self):
        return Subscription.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Save the subscription first to get the id
        subscription = serializer.save()
        # Use the database id as subscription_id
        subscription.subscription_id = str(subscription.id)
        subscription.save()

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

    # def create(self, request, *args, **kwargs):
    #     # Implement logic for creating a subscription
    #     return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        # Implement logic for updating a subscription
        return super().update(request, *args, **kwargs)

def verify_signature(payload, signature, secret_key):
    """Verify the HMAC SHA256 signature of the payload"""
    if not secret_key:
        return False
    
    expected_signature = hmac.new(
        secret_key.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected_signature)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ingest_webhook(request, sub_id):
    """Ingest a webhook for a specific subscription"""
    try:
        subscription = Subscription.objects.get(subscription_id=sub_id)
        if subscription.user != request.user:
            return Response(
                {'error': 'Not authorized to use this subscription'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get event type from header
        event_type = request.headers.get('X-Event-Type')
        if not event_type:
            return Response(
                {'error': 'Event type header (X-Event-Type) is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify event type matches subscription
        if event_type not in subscription.get_event_types():
            return Response(
                {'error': f'Subscription is not configured to receive {event_type} events'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Verify signature if secret key is configured
        if subscription.secret_key:
            signature = request.headers.get('X-Hub-Signature-256')
            if not signature:
                return Response(
                    {'error': 'Signature header (X-Hub-Signature-256) is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            if not verify_signature(request.body, signature, subscription.secret_key):
                return Response(
                    {'error': 'Invalid signature'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
        # Create initial delivery log
        delivery_log = DeliveryLog.objects.create(
            subscription=subscription,
            attempt_number=1,
            status='Queued',
            event_type=event_type
        )
            
        # Queue the webhook processing task
        process_webhook.apply_async(args=[sub_id, request.data, delivery_log.id, event_type])
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
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response(
                {'error': 'Username and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if User.objects.filter(username=username).exists():
            return Response(
                {'error': 'Username already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user = User.objects.create_user(
            username=username,
            password=password
        )
        token, created = Token.objects.get_or_create(user=user)
        # Log the user in using session authentication
        login(request, user)
        return Response({
            'token': token.key,
            'user_id': user.pk
        }, status=status.HTTP_201_CREATED)

@login_required
def logs_view(request):
    # Get all delivery logs for the current user
    logs = DeliveryLog.objects.filter(subscription__user=request.user).order_by('-timestamp')
    return render(request, 'logs.html', {'logs': logs})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subscription_attempt_history(request, sub_id):
    """Get last 20 delivery attempts for a specific subscription ID (sub_id)"""
    try:
        subscription = Subscription.objects.get(subscription_id=sub_id)
        if subscription.user != request.user:
            return Response({'error': 'Not authorized to view this subscription'}, status=403)
        logs = DeliveryLog.objects.filter(subscription=subscription).order_by('-timestamp')[:20]
        serializer = DeliveryLogSerializer(logs, many=True)
        return Response(serializer.data)
    except Subscription.DoesNotExist:
        return Response({'error': 'Subscription not found'}, status=404)

