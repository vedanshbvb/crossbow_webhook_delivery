from django.db import models
from django.contrib.auth.models import User

class Subscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='subscriptions')
    subscription_id = models.CharField(max_length=255, unique=True)
    target_url = models.URLField()
    secret_key = models.CharField(max_length=255, null=True, blank=True)  # Optional secret for signature verification
    event_types = models.TextField(default='order.created', help_text="Comma-separated list of event types this subscription is interested in")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'subscription_id']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"Subscription: {self.subscription_id}"

    def get_event_types(self):
        return [et.strip() for et in self.event_types.split(',')]

class DeliveryLog(models.Model):
    subscription = models.ForeignKey(Subscription, related_name='delivery_logs', on_delete=models.CASCADE)
    attempt_number = models.PositiveIntegerField()
    status = models.CharField(max_length=50)  # e.g., 'Success', 'Failed Attempt', 'Failure'
    http_status_code = models.IntegerField(null=True, blank=True)
    error_details = models.TextField(null=True, blank=True)
    event_type = models.CharField(max_length=255, null=True, blank=True, help_text="The event type that triggered this delivery")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['subscription', 'timestamp']),
            models.Index(fields=['status']),
            models.Index(fields=['event_type']),
        ]

    def __str__(self):
        return f"Log for {self.subscription.subscription_id} - Event: {self.event_type} - Attempt {self.attempt_number}"
