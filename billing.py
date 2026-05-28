"""Stripe billing integration."""
import json, sqlite3
from fastapi import APIRouter, Request, HTTPException

DB = "monitors.db"
router = APIRouter(prefix="/api/billing", tags=["billing"])

# Stripe webhook endpoint
@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    # Verify signature in production with stripe.Webhook.construct_event()
    event = json.loads(payload)
    event_type = event.get("type", "")

    conn = sqlite3.connect(DB)
    customer_id = event.get("data", {}).get("object", {}).get("customer")
    if event_type == "checkout.session.completed":
        conn.execute("UPDATE users SET plan = 'pro' WHERE stripe_customer_id = ?", (customer_id,))
    elif event_type == "customer.subscription.deleted":
        conn.execute("UPDATE users SET plan = 'free' WHERE stripe_customer_id = ?", (customer_id,))
    conn.commit()
    conn.close()
    return {"status": "ok"}
