from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Subscription, DeliveryLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')
        read_only_fields = ('id',)

class SubscriptionSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(write_only=True)
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Subscription
        fields = ('id', 'user_id', 'user', 'subscription_id', 'target_url', 'secret_key', 'event_types', 'created_at')
        read_only_fields = ('subscription_id', 'created_at')

    def validate_event_types(self, value):
        if not value:
            raise serializers.ValidationError("At least one event type must be specified")
        # Validate each event type format
        event_types = [et.strip() for et in value.split(',')]
        for et in event_types:
            if not et or '.' not in et:
                raise serializers.ValidationError(f"Invalid event type format: {et}. Must be in format 'type.action'")
        return value

    def create(self, validated_data):
        user_id = validated_data.pop('user_id')
        user = User.objects.get(id=user_id)
        subscription = Subscription.objects.create(user=user, **validated_data)
        return subscription

class DeliveryLogSerializer(serializers.ModelSerializer):
    subscription = SubscriptionSerializer(read_only=True)
    
    class Meta:
        model = DeliveryLog
        fields = ('id', 'subscription', 'attempt_number', 'status', 'http_status_code', 'error_details', 'event_type', 'timestamp')
        read_only_fields = ('id', 'timestamp')
