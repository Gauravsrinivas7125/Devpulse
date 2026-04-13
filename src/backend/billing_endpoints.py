"""
DevPulse - Billing Endpoints
Stripe subscription and payment management
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from typing import Dict, Any, Optional
try:
    from services.stripe_billing import billing_service, PricingTier
except ImportError:
    from ..services.stripe_billing import billing_service, PricingTier

router = APIRouter(prefix="/api/billing", tags=["billing"])

# Local auth dependency (mirrors main.py verify_token)
_security = HTTPBearer()

async def _verify_token(credentials=Depends(_security)) -> str:
    token = credentials.credentials
    if not token or not token.startswith("token_"):
        raise HTTPException(status_code=401, detail="Invalid token")
    return token.replace("token_", "")


@router.post("/create-customer")
async def create_customer(
    email: str,
    name: str,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Create a Stripe customer"""
    return billing_service.create_customer(user_id, email, name)


@router.post("/subscribe")
async def create_subscription(
    tier: PricingTier,
    customer_id: str,
    trial_days: int = 14,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Create a subscription"""
    return billing_service.create_subscription(customer_id, tier, trial_days)


@router.put("/subscription/{subscription_id}")
async def upgrade_subscription(
    subscription_id: str,
    tier: PricingTier,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Upgrade or downgrade subscription"""
    return billing_service.update_subscription(subscription_id, tier)


@router.delete("/subscription/{subscription_id}")
async def cancel_subscription(
    subscription_id: str,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Cancel a subscription"""
    return billing_service.cancel_subscription(subscription_id)


@router.get("/subscription/{subscription_id}")
async def get_subscription(
    subscription_id: str,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Get subscription details"""
    return billing_service.get_subscription(subscription_id)


@router.post("/payment-intent")
async def create_payment_intent(
    customer_id: str,
    amount: int,
    currency: str = "usd",
    description: str = "",
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Create a payment intent"""
    return billing_service.create_payment_intent(customer_id, amount, currency, description)


@router.post("/usage")
async def record_usage(
    subscription_id: str,
    quantity: int,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Record usage for metered billing"""
    return billing_service.record_usage(subscription_id, quantity)


@router.get("/invoices/{customer_id}")
async def list_invoices(
    customer_id: str,
    limit: int = 10,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """List invoices for a customer"""
    return billing_service.list_invoices(customer_id, limit)


@router.get("/invoice/{invoice_id}")
async def get_invoice(
    invoice_id: str,
    user_id: str = Depends(_verify_token)
) -> Dict[str, Any]:
    """Get invoice details"""
    return billing_service.get_invoice(invoice_id)
