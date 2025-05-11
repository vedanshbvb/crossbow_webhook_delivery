from celery import shared_task
from .models import Subscription, DeliveryLog
import requests
import time
from celery.exceptions import MaxRetriesExceededError
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=5)
def process_webhook(self, subscription_id, payload, delivery_log_id):
    logger.info(f"Processing webhook for subscription {subscription_id}, delivery_log_id: {delivery_log_id}")
    try:
        subscription = Subscription.objects.get(subscription_id=subscription_id)
        url = subscription.target_url
        logger.info(f"Target URL: {url}")
        
        # Calculate retry delay based on attempt number
        retry_delays = [10, 30, 60, 300, 900]  # 10s, 30s, 1m, 5m, 15m
        current_attempt = self.request.retries + 1
        logger.info(f"Current attempt: {current_attempt}")
        
        try:
            logger.info("Sending POST request to target URL")
            response = requests.post(url, json=payload, timeout=10)
            status = 'Success' if response.status_code == 200 else 'Failed Attempt'
            logger.info(f"Response status code: {response.status_code}")
            
            # Update the existing delivery log
            delivery_log = DeliveryLog.objects.get(id=delivery_log_id)
            delivery_log.status = status
            delivery_log.http_status_code = response.status_code
            delivery_log.save()
            logger.info(f"Updated delivery log status to: {status}")
            
            if response.status_code != 200:
                raise Exception(f"Target returned status code {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error processing webhook: {str(e)}")
            # Update the delivery log with failure
            delivery_log = DeliveryLog.objects.get(id=delivery_log_id)
            delivery_log.status = 'Failed Attempt'
            delivery_log.error_details = str(e)
            delivery_log.save()
            
            # Retry with exponential backoff
            if current_attempt <= len(retry_delays):
                delay = retry_delays[current_attempt - 1]
                logger.info(f"Scheduling retry in {delay} seconds")
                raise self.retry(exc=e, countdown=delay)
            else:
                # Mark as final failure after all retries
                logger.error("Max retries exceeded")
                delivery_log.status = 'Failure'
                delivery_log.error_details = f"Max retries exceeded: {str(e)}"
                delivery_log.save()
                raise MaxRetriesExceededError()
                
    except Subscription.DoesNotExist:
        logger.error(f"Subscription {subscription_id} not found")
        # Update delivery log with subscription not found error
        delivery_log = DeliveryLog.objects.get(id=delivery_log_id)
        delivery_log.status = 'Failure'
        delivery_log.error_details = 'Subscription not found'
        delivery_log.save()
        raise

@shared_task
def cleanup_old_logs():
    """
    Cleanup delivery logs older than 72 hours
    """
    cutoff_time = timezone.now() - timedelta(hours=72)
    DeliveryLog.objects.filter(timestamp__lt=cutoff_time).delete()
