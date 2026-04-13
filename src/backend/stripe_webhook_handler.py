"""
DevPulse - Stripe Webhook Handler with Signature Verification
Handles Stripe payment events and subscription updates via database
"""

import os
import logging
import stripe
from typing import Dict, Any, Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Price ID to plan mapping - configure via env vars for production
STRIPE_PRICE_MAP: Dict[str, str] = {
    os.getenv("STRIPE_PRO_PRICE_ID", "price_pro_monthly"): "pro",
    os.getenv("STRIPE_PRO_YEARLY_PRICE_ID", "price_pro_yearly"): "pro",
    os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_enterprise_monthly"): "enterprise",
    os.getenv("STRIPE_ENTERPRISE_YEARLY_PRICE_ID", "price_enterprise_yearly"): "enterprise",
}


class StripeWebhookHandler:
    """Handle Stripe webhook events with proper signature verification and DB persistence"""

    def __init__(self, user_lookup: Callable):
        """
        Args:
            user_lookup: callable that accepts a stripe_customer_id and returns
                         a DB User ORM object (or None). The caller is responsible
                         for committing any mutations.
        """
        self.user_lookup = user_lookup
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

        handlers = {
            "customer.subscription.updated": self._handle_subscription_updated,
            "customer.subscription.deleted": self._handle_subscription_deleted,
            "charge.succeeded": self._handle_charge_succeeded,
            "charge.failed": self._handle_charge_failed,
            "invoice.payment_succeeded": self._handle_invoice_payment_succeeded,
            "invoice.payment_failed": self._handle_invoice_payment_failed,
        }

        handler = handlers.get(event_type)
        if handler:
            return handler(data)

        logger.info(f"Unhandled event type: {event_type}")
        return {"success": True, "message": "Event received but not processed"}

    def _handle_subscription_updated(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription updated event - persists plan change to DB"""
        customer_id = subscription.get("customer")
        sub_status = subscription.get("status")

        user = self._find_user_by_stripe_customer(customer_id)
        if not user:
            logger.warning(f"User not found for customer {customer_id}")
            return {"success": False, "error": "User not found"}

        plan = self._extract_plan_from_subscription(subscription)

        # Persist to database via ORM model
        user.subscription_status = sub_status
        user.plan = plan

        logger.info(f"Updated subscription for user {user.email}: {sub_status} ({plan})")

        return {
            "success": True,
            "message": "Subscription updated",
            "user_id": user.id,
            "plan": plan,
            "status": sub_status,
        }

    def _handle_subscription_deleted(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription cancelled event - downgrades user to free in DB"""
        customer_id = subscription.get("customer")

        user = self._find_user_by_stripe_customer(customer_id)
        if not user:
            return {"success": False, "error": "User not found"}

        user.plan = "free"
        user.subscription_status = "canceled"

        logger.info(f"Cancelled subscription for user {user.email}")

        return {
            "success": True,
            "message": "Subscription cancelled",
            "user_id": user.id,
            "plan": "free",
        }

    def _handle_charge_succeeded(self, charge: Dict[str, Any]) -> Dict[str, Any]:
        """Handle charge succeeded event"""
        customer_id = charge.get("customer")
        amount = (charge.get("amount") or 0) / 100  # Convert from cents

        logger.info(f"Charge succeeded: ${amount} for customer {customer_id}")

        return {
            "success": True,
            "message": "Charge processed",
            "amount": amount,
        }

    def _handle_charge_failed(self, charge: Dict[str, Any]) -> Dict[str, Any]:
        """Handle charge failed event - marks subscription as past_due in DB"""
        customer_id = charge.get("customer")
        error_message = charge.get("failure_message", "Unknown error")

        user = self._find_user_by_stripe_customer(customer_id)
        if user:
            user.subscription_status = "past_due"

        logger.warning(f"Charge failed for customer {customer_id}: {error_message}")

        return {
            "success": True,
            "message": "Charge failed",
            "error": error_message,
        }

    def _handle_invoice_payment_succeeded(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice payment succeeded event"""
        customer_id = invoice.get("customer")
        amount = (invoice.get("total") or 0) / 100

        logger.info(f"Invoice payment succeeded: ${amount} for customer {customer_id}")

        return {
            "success": True,
            "message": "Invoice paid",
            "amount": amount,
        }

    def _handle_invoice_payment_failed(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice payment failed event - marks subscription as past_due in DB"""
        customer_id = invoice.get("customer")

        user = self._find_user_by_stripe_customer(customer_id)
        if user:
            user.subscription_status = "past_due"

        logger.warning(f"Invoice payment failed for customer {customer_id}")

        return {
            "success": True,
            "message": "Invoice payment failed",
        }

    def _find_user_by_stripe_customer(self, customer_id: str):
        """Find user by Stripe customer ID using the injected DB lookup"""
        if not customer_id:
            return None
        return self.user_lookup(customer_id)

    def _extract_plan_from_subscription(self, subscription: Dict[str, Any]) -> str:
        """Extract plan name from Stripe subscription using price ID mapping"""
        try:
            items = subscription.get("items", {}).get("data", [])
            if items:
                price_id = items[0].get("price", {}).get("id", "")
                if not price_id:
                    return "free"
                # Check explicit mapping first
                mapped = STRIPE_PRICE_MAP.get(price_id)
                if mapped:
                    return mapped
                # Fallback heuristic on price ID naming
                price_lower = price_id.lower()
                if "enterprise" in price_lower:
                    return "enterprise"
                if "pro" in price_lower:
                    return "pro"
            return "free"
        except Exception as e:
            logger.error(f"Error extracting plan: {str(e)}")
            return "free"


def get_webhook_handler(user_lookup: Callable) -> StripeWebhookHandler:
    """Factory function to get webhook handler with a DB-backed user lookup"""
    return StripeWebhookHandler(user_lookup)
