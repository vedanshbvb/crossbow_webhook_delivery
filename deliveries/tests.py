from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from .models import Subscription, DeliveryLog
from .tasks import process_webhook, cleanup_old_logs
from django.utils import timezone
from datetime import timedelta
import json

class ModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.subscription = Subscription.objects.create(
            user=self.user,
            subscription_id='test-sub-1',
            target_url='http://example.com/webhook',
            secret_key='test-secret'
        )

    def test_subscription_creation(self):
        self.assertEqual(self.subscription.user, self.user)
        self.assertEqual(self.subscription.subscription_id, 'test-sub-1')
        self.assertEqual(self.subscription.target_url, 'http://example.com/webhook')
        self.assertEqual(self.subscription.secret_key, 'test-secret')

    def test_delivery_log_creation(self):
        log = DeliveryLog.objects.create(
            subscription=self.subscription,
            attempt_number=1,
            status='Success',
            http_status_code=200
        )
        self.assertEqual(log.subscription, self.subscription)
        self.assertEqual(log.attempt_number, 1)
        self.assertEqual(log.status, 'Success')
        self.assertEqual(log.http_status_code, 200)

class ViewTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        self.subscription = Subscription.objects.create(
            user=self.user,
            subscription_id='test-sub-1',
            target_url='http://example.com/webhook',
            secret_key='test-secret'
        )

    def test_create_subscription(self):
        url = reverse('subscription-list')
        data = {
            'subscription_id': 'test-sub-2',
            'target_url': 'http://example.com/webhook2',
            'secret_key': 'test-secret-2'
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Subscription.objects.count(), 2)

    def test_list_subscriptions(self):
        url = reverse('subscription-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_ingest_webhook(self):
        url = reverse('ingest-webhook', args=[self.subscription.subscription_id])
        data = {'test': 'data'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

    def test_delivery_status(self):
        log = DeliveryLog.objects.create(
            subscription=self.subscription,
            attempt_number=1,
            status='Success',
            http_status_code=200
        )
        url = reverse('delivery-status', args=[log.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'Success')

class TaskTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.subscription = Subscription.objects.create(
            user=self.user,
            subscription_id='test-sub-1',
            target_url='http://example.com/webhook',
            secret_key='test-secret'
        )

    def test_cleanup_old_logs(self):
        # Create old logs
        old_time = timezone.now() - timedelta(hours=73)
        DeliveryLog.objects.create(
            subscription=self.subscription,
            attempt_number=1,
            status='Success',
            http_status_code=200,
            timestamp=old_time
        )
        
        # Create recent logs
        DeliveryLog.objects.create(
            subscription=self.subscription,
            attempt_number=1,
            status='Success',
            http_status_code=200
        )
        
        # Run cleanup
        cleanup_old_logs()
        
        # Check if only recent logs remain
        self.assertEqual(DeliveryLog.objects.count(), 1)
        self.assertEqual(
            DeliveryLog.objects.first().timestamp.date(),
            timezone.now().date()
        )
