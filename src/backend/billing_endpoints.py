"""
DevPulse - Billing Endpoints
Stripe subscription and payment management
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional

try:
    from services.stripe_billing import billing_service, PricingTier
except ImportError:
    from ..services.stripe_billing import billing_service, PricingTier

from .models import User
from .database import get_db
from .auth import verify_token as _verify_token  # shared auth module

router = APIRouter(prefix="/api/billing", tags=["billing"])


def _get_user_stripe_customer_id(db: Session, user_id: str) -> str:
    """Get the authenticated user's stripe_customer_id or raise 400."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No Stripe customer linked to this account.")
    return user.stripe_customer_id


def _verify_subscription_ownership(db: Session, user_id: str, subscription_id: str) -> None:
    """Verify that a subscription belongs to the authenticated user's Stripe customer."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.stripe_customer_id:
        raise HTTPException(status_code=403, detail="You do not have an active billing account.")
    if user.stripe_subscription_id == subscription_id:
        return
    # No match — reject access
    raise HTTPException(status_code=403, detail="This subscription does not belong to your account.")


@router.post("/create-customer")
async def create_customer(
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Create a Stripe customer using the authenticated user's email and name."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return billing_service.create_customer(user_id, user.email, user.name)


@router.post("/subscribe")
async def create_subscription(
    tier: PricingTier,
    customer_id: str,
    trial_days: int = 14,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Create a subscription"""
    # Verify the customer_id belongs to this user
    own_customer_id = _get_user_stripe_customer_id(db, user_id)
    if customer_id != own_customer_id:
        raise HTTPException(status_code=403, detail="Cannot create subscription for another customer.")
    return billing_service.create_subscription(customer_id, tier, trial_days)


@router.put("/subscription/{subscription_id}")
async def upgrade_subscription(
    subscription_id: str,
    tier: PricingTier,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Upgrade or downgrade subscription"""
    _verify_subscription_ownership(db, user_id, subscription_id)
    return billing_service.update_subscription(subscription_id, tier)


@router.delete("/subscription/{subscription_id}")
async def cancel_subscription(
    subscription_id: str,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Cancel a subscription"""
    _verify_subscription_ownership(db, user_id, subscription_id)
    return billing_service.cancel_subscription(subscription_id)


@router.get("/subscription/{subscription_id}")
async def get_subscription(
    subscription_id: str,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get subscription details"""
    _verify_subscription_ownership(db, user_id, subscription_id)
    return billing_service.get_subscription(subscription_id)


@router.post("/payment-intent")
async def create_payment_intent(
    customer_id: str,
    amount: int,
    currency: str = "usd",
    description: str = "",
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Create a payment intent"""
    own_customer_id = _get_user_stripe_customer_id(db, user_id)
    if customer_id != own_customer_id:
        raise HTTPException(status_code=403, detail="Cannot create payment intent for another customer.")
    return billing_service.create_payment_intent(customer_id, amount, currency, description)


@router.post("/usage")
async def record_usage(
    subscription_id: str,
    quantity: int,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Record usage for metered billing"""
    _verify_subscription_ownership(db, user_id, subscription_id)
    return billing_service.record_usage(subscription_id, quantity)


@router.get("/invoices/{customer_id}")
async def list_invoices(
    customer_id: str,
    limit: int = 10,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """List invoices for a customer"""
    own_customer_id = _get_user_stripe_customer_id(db, user_id)
    if customer_id != own_customer_id:
        raise HTTPException(status_code=403, detail="Cannot view invoices for another customer.")
    return billing_service.list_invoices(customer_id, limit)


@router.get("/invoice/{invoice_id}")
async def get_invoice(
    invoice_id: str,
    user_id: str = Depends(_verify_token),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Get invoice details (ownership enforced via customer check)"""
    # Ensure user has a linked Stripe customer before allowing invoice access
    _get_user_stripe_customer_id(db, user_id)
    return billing_service.get_invoice(invoice_id)
