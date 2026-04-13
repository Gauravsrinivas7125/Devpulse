"""
DevPulse - Stripe Webhook Handler with Signature Verification
Handles Stripe payment events and subscription updates
"""

import os
import json
import logging
import stripe
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")


class StripeWebhookHandler:
    """Handle Stripe webhook events with proper signature verification"""
    
    def __init__(self, users_db: Dict[str, Any]):
        self.users_db = users_db
        self.webhook_secret = STRIPE_WEBHOOK_SECRET

    def verify_and_process_webhook(self, request_body: str, signature: str) -> Dict[str, Any]:
        """
        Verify Stripe webhook signature and process the event
        
        SECURITY: This prevents spoofed webhook events
        """
        try:
            # SECURITY FIX: Verify webhook signature
            if not self.webhook_secret:
                logger.error("STRIPE_WEBHOOK_SECRET not configured")
                return {"success": False, "error": "Webhook processing failed"}
            
            event = stripe.Webhook.construct_event(
                request_body,
                signature,
                self.webhook_secret
            )
            
            logger.info(f"Webhook verified: {event['type']}")
            
            # Process the event
            return self._process_event(event)
        
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Webhook signature verification failed: {str(e)}")
            return {"success": False, "error": "Invalid signature"}
        except Exception as e:
            logger.error(f"Webhook processing error: {str(e)}")
            return {"success": False, "error": "Webhook processing failed"}

    def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process verified webhook event"""
        event_type = event["type"]
        data = event["data"]["object"]
        
        if event_type == "customer.subscription.updated":
            return self._handle_subscription_updated(data)
        elif event_type == "customer.subscription.deleted":
            return self._handle_subscription_deleted(data)
        elif event_type == "charge.succeeded":
            return self._handle_charge_succeeded(data)
        elif event_type == "charge.failed":
            return self._handle_charge_failed(data)
        elif event_type == "invoice.payment_succeeded":
            return self._handle_invoice_payment_succeeded(data)
        elif event_type == "invoice.payment_failed":
            return self._handle_invoice_payment_failed(data)
        else:
            logger.info(f"Unhandled event type: {event_type}")
            return {"success": True, "message": "Event received but not processed"}

    def _handle_subscription_updated(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updated event"""
        customer_id = subscription.get("customer")
        status = subscription.get("status")
        
        # Find user by Stripe customer ID
        user = self._find_user_by_stripe_customer(customer_id)
        if not user:
            logger.warning(f"User not found for customer {customer_id}")
            return {"success": False, "error": "User not found"}
        
        # Get plan from subscription
        plan = self._extract_plan_from_subscription(subscription)
        
        # Update user's subscription
        user["subscription_status"] = status
        user["plan"] = plan
        user["updated_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Updated subscription for user {user.get('email')}: {status} ({plan})")
        
        return {
            "success": True,
            "message": "Subscription updated",
            "user_id": user.get("id"),
            "plan": plan,
            "status": status
        }

    def _handle_subscription_deleted(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription cancelled event"""
        customer_id = subscription.get("customer")
        
        user = self._find_user_by_stripe_customer(customer_id)
        if not user:
            return {"success": False, "error": "User not found"}
        
        # Downgrade to free plan
        user["plan"] = "free"
        user["subscription_status"] = "canceled"
        user["updated_at"] = datetime.utcnow().isoformat()
        
        logger.info(f"Cancelled subscription for user {user.get('email')}")
        
        return {
            "success": True,
            "message": "Subscription cancelled",
            "user_id": user.get("id"),
            "plan": "free"
        }

    def _handle_charge_succeeded(self, charge: Dict[str, Any]) -> Dict[str, Any]:
        """Handle charge succeeded event"""
        customer_id = charge.get("customer")
        amount = (charge.get("amount") or 0) / 100  # Convert from cents
        
        logger.info(f"Charge succeeded: ${amount} for customer {customer_id}")
        
        return {
            "success": True,
            "message": "Charge processed",
            "amount": amount
        }

    def _handle_charge_failed(self, charge: Dict[str, Any]) -> Dict[str, Any]:
        """Handle charge failed event"""
        customer_id = charge.get("customer")
        error_message = charge.get("failure_message", "Unknown error")
        
        user = self._find_user_by_stripe_customer(customer_id)
        if user:
            user["subscription_status"] = "past_due"
        
        logger.warning(f"Charge failed for customer {customer_id}: {error_message}")
        
        return {
            "success": True,
            "message": "Charge failed",
            "error": error_message
        }

    def _handle_invoice_payment_succeeded(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice payment succeeded event"""
        customer_id = invoice.get("customer")
        amount = (invoice.get("total") or 0) / 100
        
        logger.info(f"Invoice payment succeeded: ${amount} for customer {customer_id}")
        
        return {
            "success": True,
            "message": "Invoice paid",
            "amount": amount
        }

    def _handle_invoice_payment_failed(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice payment failed event"""
        customer_id = invoice.get("customer")
        
        user = self._find_user_by_stripe_customer(customer_id)
        if user:
            user["subscription_status"] = "past_due"
        
        logger.warning(f"Invoice payment failed for customer {customer_id}")
        
        return {
            "success": True,
            "message": "Invoice payment failed"
        }

    def _find_user_by_stripe_customer(self, customer_id: str) -> Optional[Dict[str, Any]]:
        """Find user by Stripe customer ID"""
        for user_id, user in self.users_db.items():
            if user.get("stripe_customer_id") == customer_id:
                return user
        return None

    def _extract_plan_from_subscription(self, subscription: Dict[str, Any]) -> str:
        """Extract plan name from subscription"""
        try:
            items = subscription.get("items", {}).get("data", [])
            if items:
                price_id = items[0].get("price", {}).get("id")
                if not price_id:
                    return "free"
                # Map price ID to plan name
                if "pro" in price_id:
                    return "pro"
                elif "enterprise" in price_id:
                    return "enterprise"
            return "free"
        except Exception as e:
            logger.error(f"Error extracting plan: {str(e)}")
            return "free"


def get_webhook_handler(users_db: Dict[str, Any]) -> StripeWebhookHandler:
    """Factory function to get webhook handler"""
    return StripeWebhookHandler(users_db)
