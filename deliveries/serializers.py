from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Subscription, DeliveryLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')
        read_only_fields = ('id',)

class SubscriptionSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Subscription
        fields = ('id', 'user', 'subscription_id', 'target_url', 'secret_key', 'created_at')
        read_only_fields = ('id', 'user', 'created_at')

class DeliveryLogSerializer(serializers.ModelSerializer):
    subscription = SubscriptionSerializer(read_only=True)
    
    class Meta:
        model = DeliveryLog
        fields = ('id', 'subscription', 'attempt_number', 'status', 
                 'http_status_code', 'error_details', 'timestamp')
        read_only_fields = ('id', 'timestamp')
