# DevPulse Operational Runbooks

## 1. Redis Recovery & Scaling
**Status:** Critical
**Owner:** DevOps Team

### Issue: Redis Connection Failure
1. **Identify**: Check logs for `ConnectionError` or `TimeoutError` from Redis client.
2. **Immediate Action**: 
   - Check Redis service status: `systemctl status redis`
   - Restart Redis if down: `sudo systemctl restart redis`
3. **Verification**: Run `redis-cli ping`. Expected response: `PONG`.
4. **Escalation**: If persistent, check for OOM (Out of Memory) in `/var/log/syslog`.

### Issue: Usage Counter Inconsistency
1. **Identify**: User reports "Limit Exceeded" but usage dashboard shows available credits.
2. **Fix**: Run the usage sync script: `python3 scripts/sync_usage_redis_db.py --user_id <ID>`
3. **Root Cause**: Check for race conditions or network partitions between app and Redis.

---

## 2. Stripe Billing Integration
**Status:** High
**Owner:** Finance/Product

### Issue: Webhook Delivery Failure
1. **Identify**: Check Stripe Dashboard > Developers > Webhooks for failed deliveries (4xx/5xx).
2. **Fix**: 
   - Verify `STRIPE_WEBHOOK_SECRET` in environment variables.
   - Check backend logs for `StripeSignatureError`.
3. **Manual Sync**: If a payment succeeded but plan didn't upgrade, use the admin tool:
   `python3 scripts/admin_upgrade_plan.py --user_id <ID> --plan <PLAN>`

### Issue: Subscription Cancellation Sync
1. **Identify**: User cancelled in Stripe but still has PRO access.
2. **Action**: Verify `customer.subscription.deleted` event was received.
3. **Fix**: Manually downgrade user: `curl -X POST https://api.devpulse.com/admin/downgrade -H "Authorization: Bearer $ADMIN_KEY" -d '{"user_id": "..."}'`

---

## 3. AgentGuard Kill Switch (Emergency)
**Status:** Critical (Emergency)
**Owner:** Security Lead

### Scenario: Malicious LLM Behavior Detected
1. **Identify**: `AgentGuard` alerts triggered in Slack/PagerDuty.
2. **Immediate Action**: Enable Global Kill Switch.
   - **API**: `POST /api/kill-switch/block?reason=Emergency_Malicious_Activity`
   - **Manual**: Set `KILL_SWITCH_ENABLED=true` in Railway/Docker env and redeploy.
3. **Verification**: Verify all outbound LLM requests are returning `403 Forbidden`.
4. **Resolution**: 
   - Analyze the blocked request patterns.
   - Update `kill_switch.py` blocklist with new malicious patterns.
   - Disable kill switch once safe.

---

## 4. Production Deployment (One-Click)
**Status:** Normal
**Owner:** DevOps

### Process:
1. Ensure all tests pass: `npm test && pytest`
2. Merge to `main` branch.
3. GitHub Action will:
   - Build Docker image.
   - Push to registry.
   - Deploy to Railway/K8s.
4. Verify health: `curl https://api.devpulse.com/api/health`
