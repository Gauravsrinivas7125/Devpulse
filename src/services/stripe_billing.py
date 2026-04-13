"""
DevPulse - Stripe Billing Integration
Subscription management, payment processing, and usage-based billing
"""

import os
import stripe
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_API_KEY", "sk_test_devpulse")


class PricingTier(str, Enum):
    """Pricing tiers"""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    """Subscription status"""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    TRIALING = "trialing"


class StripeBillingService:
    """Stripe billing and subscription management"""
    
    def __init__(self):
        self.stripe_key = stripe.api_key
    
    def create_customer(self, user_id: str, email: str, name: str) -> Dict[str, Any]:
        """Create a Stripe customer"""
        try:
            customer = stripe.Customer.create(
                email=email,
                name=name,
                metadata={"user_id": user_id}
            )
            logger.info(f"Created Stripe customer {customer.id} for user {user_id}")
            return {
                "success": True,
                "customer_id": customer.id,
                "email": customer.email
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_subscription(
        self,
        customer_id: str,
        tier: PricingTier,
        trial_days: int = 14
    ) -> Dict[str, Any]:
        """Create a subscription for a customer"""
        try:
            # Map tier to Stripe price ID
            price_ids = {
                PricingTier.FREE: "price_free",
                PricingTier.PRO: os.getenv("STRIPE_PRICE_PRO", "price_pro"),
                PricingTier.ENTERPRISE: os.getenv("STRIPE_PRICE_ENTERPRISE", "price_enterprise")
            }
            
            price_id = price_ids.get(tier)
            if not price_id:
                return {"success": False, "error": f"Unknown tier: {tier}"}
            
            # Create subscription
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{"price": price_id}],
                trial_period_days=trial_days if tier != PricingTier.FREE else 0,
                payment_behavior="default_incomplete"
            )
            
            logger.info(f"Created subscription {subscription.id} for customer {customer_id}")
            return {
                "success": True,
                "subscription_id": subscription.id,
                "status": subscription.status,
                "current_period_end": subscription.current_period_end,
                "trial_end": subscription.trial_end
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create subscription: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def update_subscription(
        self,
        subscription_id: str,
        tier: PricingTier
    ) -> Dict[str, Any]:
        """Upgrade or downgrade a subscription"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            # Map tier to Stripe price ID
            price_ids = {
                PricingTier.FREE: "price_free",
                PricingTier.PRO: os.getenv("STRIPE_PRICE_PRO", "price_pro"),
                PricingTier.ENTERPRISE: os.getenv("STRIPE_PRICE_ENTERPRISE", "price_enterprise")
            }
            
            price_id = price_ids.get(tier)
            if not price_id:
                return {"success": False, "error": f"Unknown tier: {tier}"}
            
            # Update subscription
            updated_subscription = stripe.Subscription.modify(
                subscription_id,
                items=[{
                    "id": subscription.items.data[0].id,
                    "price": price_id
                }]
            )
            
            logger.info(f"Updated subscription {subscription_id} to tier {tier}")
            return {
                "success": True,
                "subscription_id": updated_subscription.id,
                "status": updated_subscription.status
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to update subscription: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def cancel_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Cancel a subscription"""
        try:
            subscription = stripe.Subscription.delete(subscription_id)
            logger.info(f"Canceled subscription {subscription_id}")
            return {
                "success": True,
                "subscription_id": subscription.id,
                "status": subscription.status
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to cancel subscription: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """Get subscription details"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            return {
                "success": True,
                "subscription_id": subscription.id,
                "status": subscription.status,
                "customer_id": subscription.customer,
                "current_period_start": subscription.current_period_start,
                "current_period_end": subscription.current_period_end,
                "trial_end": subscription.trial_end,
                "items": [
                    {
                        "price_id": item.price.id,
                        "amount": item.price.unit_amount,
                        "currency": item.price.currency
                    }
                    for item in subscription.items.data
                ]
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to get subscription: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_payment_intent(
        self,
        customer_id: str,
        amount: int,
        currency: str = "usd",
        description: str = ""
    ) -> Dict[str, Any]:
        """Create a payment intent for one-time charges"""
        try:
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency=currency,
                customer=customer_id,
                description=description
            )
            logger.info(f"Created payment intent {intent.id} for customer {customer_id}")
            return {
                "success": True,
                "payment_intent_id": intent.id,
                "client_secret": intent.client_secret,
                "status": intent.status
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create payment intent: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def record_usage(
        self,
        subscription_id: str,
        quantity: int,
        timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Record usage for metered billing"""
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            
            # Find metered price
            metered_item = None
            for item in subscription.items.data:
                if item.price.billing_scheme == "tiered":
                    metered_item = item
                    break
            
            if not metered_item:
                return {"success": False, "error": "No metered billing item found"}
            
            # Record usage
            usage_record = stripe.SubscriptionItem.create_usage_record(
                metered_item.id,
                quantity=quantity,
                timestamp=int((timestamp or datetime.utcnow()).timestamp())
            )
            
            logger.info(f"Recorded {quantity} usage units for subscription {subscription_id}")
            return {
                "success": True,
                "usage_record_id": usage_record.id,
                "quantity": usage_record.quantity
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to record usage: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_invoice(self, invoice_id: str) -> Dict[str, Any]:
        """Get invoice details"""
        try:
            invoice = stripe.Invoice.retrieve(invoice_id)
            return {
                "success": True,
                "invoice_id": invoice.id,
                "amount": invoice.amount_paid,
                "status": invoice.status,
                "pdf_url": invoice.invoice_pdf,
                "created": invoice.created,
                "due_date": invoice.due_date
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to get invoice: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_invoices(self, customer_id: str, limit: int = 10) -> Dict[str, Any]:
        """List invoices for a customer"""
        try:
            invoices = stripe.Invoice.list(customer=customer_id, limit=limit)
            return {
                "success": True,
                "invoices": [
                    {
                        "invoice_id": inv.id,
                        "amount": inv.amount_paid,
                        "status": inv.status,
                        "created": inv.created,
                        "pdf_url": inv.invoice_pdf
                    }
                    for inv in invoices.data
                ]
            }
        except stripe.error.StripeError as e:
            logger.error(f"Failed to list invoices: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }


# Global billing service instance
billing_service = StripeBillingService()
