"""
DevPulse Webhook Integrations Service
Multi-platform webhook notifications for scan results,
anomaly alerts, and compliance events.
Supports Slack, Discord, Microsoft Teams, and generic webhooks.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import threading


class WebhookPlatform(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    GENERIC = "generic"


class WebhookEventType(str, Enum):
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    CRITICAL_FINDING = "finding.critical"
    HIGH_FINDING = "finding.high"
    RISK_SCORE_CHANGE = "risk.score_change"
    COMPLIANCE_REPORT = "compliance.report_generated"
    COST_ANOMALY = "cost.anomaly"
    COST_BUDGET_WARNING = "cost.budget_warning"
    KILL_SWITCH_ACTIVATED = "killswitch.activated"
    KILL_SWITCH_DEACTIVATED = "killswitch.deactivated"
    SHADOW_API_DETECTED = "shadow_api.detected"


@dataclass
class WebhookConfig:
    webhook_id: str
    user_id: str
    name: str
    platform: WebhookPlatform
    url: str
    events: List[WebhookEventType]
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    headers: Dict[str, str] = field(default_factory=dict)
    secret: Optional[str] = None


@dataclass
class WebhookDelivery:
    delivery_id: str
    webhook_id: str
    event_type: WebhookEventType
    payload: Dict
    status: str  # "pending", "delivered", "failed"
    response_code: Optional[int] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    retry_count: int = 0


class WebhookIntegrationService:
    """
    Multi-platform webhook service for sending notifications
    about security events, scan results, and cost alerts.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._webhooks: Dict[str, WebhookConfig] = {}
        self._deliveries: List[WebhookDelivery] = []
        self._delivery_counter = 0

    # -----------------------------------------------------------------------
    # Webhook CRUD
    # -----------------------------------------------------------------------

    def register_webhook(
        self,
        user_id: str,
        name: str,
        platform: str,
        url: str,
        events: List[str],
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
    ) -> WebhookConfig:
        """Register a new webhook endpoint."""
        with self._lock:
            webhook_id = f"wh_{len(self._webhooks) + 1}_{int(datetime.utcnow().timestamp())}"
            config = WebhookConfig(
                webhook_id=webhook_id,
                user_id=user_id,
                name=name,
                platform=WebhookPlatform(platform),
                url=url,
                events=[WebhookEventType(e) for e in events],
                headers=headers or {},
                secret=secret,
            )
            self._webhooks[webhook_id] = config
            return config

    def get_webhooks(self, user_id: str) -> List[Dict]:
        """Get all webhooks for a user."""
        with self._lock:
            return [
                {
                    "webhook_id": wh.webhook_id,
                    "name": wh.name,
                    "platform": wh.platform.value,
                    "url": wh.url[:50] + "..." if len(wh.url) > 50 else wh.url,
                    "events": [e.value for e in wh.events],
                    "enabled": wh.enabled,
                    "created_at": wh.created_at,
                }
                for wh in self._webhooks.values()
                if wh.user_id == user_id
            ]

    def update_webhook(
        self,
        webhook_id: str,
        user_id: str,
        updates: Dict,
    ) -> Optional[Dict]:
        """Update a webhook configuration."""
        with self._lock:
            wh = self._webhooks.get(webhook_id)
            if not wh or wh.user_id != user_id:
                return None

            if "name" in updates:
                wh.name = updates["name"]
            if "url" in updates:
                wh.url = updates["url"]
            if "events" in updates:
                wh.events = [WebhookEventType(e) for e in updates["events"]]
            if "enabled" in updates:
                wh.enabled = updates["enabled"]
            if "headers" in updates:
                wh.headers = updates["headers"]

            return {"webhook_id": webhook_id, "status": "updated"}

    def delete_webhook(self, webhook_id: str, user_id: str) -> bool:
        """Delete a webhook."""
        with self._lock:
            wh = self._webhooks.get(webhook_id)
            if not wh or wh.user_id != user_id:
                return False
            del self._webhooks[webhook_id]
            return True

    # -----------------------------------------------------------------------
    # Payload Formatters (platform-specific)
    # -----------------------------------------------------------------------

    def _format_slack_payload(self, event_type: str, data: Dict) -> Dict:
        """Format payload for Slack incoming webhook."""
        severity_emoji = {
            "CRITICAL": ":red_circle:",
            "HIGH": ":large_orange_circle:",
            "MEDIUM": ":large_yellow_circle:",
            "LOW": ":large_blue_circle:",
            "INFO": ":white_circle:",
        }

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"DevPulse Alert: {event_type.replace('.', ' ').title()}",
                },
            },
        ]

        if event_type.startswith("scan."):
            risk = data.get("risk_score", 0)
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Risk Score:* {risk}/100"},
                    {"type": "mrkdwn", "text": f"*Findings:* {data.get('total_findings', 0)}"},
                    {"type": "mrkdwn", "text": f"*Collection:* {data.get('collection_name', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Status:* {data.get('status', 'N/A')}"},
                ],
            })
        elif event_type.startswith("finding."):
            sev = data.get("severity", "INFO")
            emoji = severity_emoji.get(sev, ":white_circle:")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{sev}* - {data.get('title', 'Unknown Finding')}\n{data.get('description', '')}",
                },
            })
        elif event_type.startswith("cost."):
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":money_with_wings: {data.get('message', 'Cost alert triggered')}",
                },
            })

        return {"blocks": blocks}

    def _format_discord_payload(self, event_type: str, data: Dict) -> Dict:
        """Format payload for Discord webhook."""
        color_map = {
            "CRITICAL": 0xFF0000,
            "HIGH": 0xFF8C00,
            "MEDIUM": 0xFFD700,
            "LOW": 0x4169E1,
            "INFO": 0x808080,
        }

        embed = {
            "title": f"DevPulse: {event_type.replace('.', ' ').title()}",
            "color": color_map.get(data.get("severity", "INFO"), 0x808080),
            "timestamp": datetime.utcnow().isoformat(),
            "footer": {"text": "DevPulse Security Intelligence"},
            "fields": [],
        }

        if event_type.startswith("scan."):
            embed["fields"] = [
                {"name": "Risk Score", "value": str(data.get("risk_score", 0)), "inline": True},
                {"name": "Findings", "value": str(data.get("total_findings", 0)), "inline": True},
                {"name": "Collection", "value": data.get("collection_name", "N/A"), "inline": True},
            ]
        elif event_type.startswith("finding."):
            embed["description"] = data.get("description", "")
            embed["fields"] = [
                {"name": "Severity", "value": data.get("severity", "INFO"), "inline": True},
                {"name": "Category", "value": data.get("category", "N/A"), "inline": True},
            ]
        elif event_type.startswith("cost."):
            embed["description"] = data.get("message", "Cost alert")

        return {"embeds": [embed]}

    def _format_teams_payload(self, event_type: str, data: Dict) -> Dict:
        """Format payload for Microsoft Teams webhook (Adaptive Card)."""
        facts = []
        if event_type.startswith("scan."):
            facts = [
                {"title": "Risk Score", "value": str(data.get("risk_score", 0))},
                {"title": "Findings", "value": str(data.get("total_findings", 0))},
                {"title": "Collection", "value": data.get("collection_name", "N/A")},
                {"title": "Status", "value": data.get("status", "N/A")},
            ]
        elif event_type.startswith("finding."):
            facts = [
                {"title": "Severity", "value": data.get("severity", "INFO")},
                {"title": "Category", "value": data.get("category", "N/A")},
                {"title": "Description", "value": data.get("description", "")},
            ]
        elif event_type.startswith("cost."):
            facts = [
                {"title": "Alert", "value": data.get("message", "Cost alert")},
            ]

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if "critical" in event_type else "FFA500",
            "summary": f"DevPulse: {event_type}",
            "sections": [{
                "activityTitle": f"DevPulse Alert: {event_type.replace('.', ' ').title()}",
                "facts": facts,
                "markdown": True,
            }],
        }

    def _format_generic_payload(self, event_type: str, data: Dict) -> Dict:
        """Format payload for generic webhook."""
        return {
            "event": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "devpulse",
            "version": "1.0",
        }

    # -----------------------------------------------------------------------
    # Dispatch
    # -----------------------------------------------------------------------

    def dispatch(self, event_type: str, data: Dict, user_id: Optional[str] = None) -> List[Dict]:
        """
        Dispatch an event to all matching webhooks.
        Returns list of delivery records.
        In production, this would use httpx/aiohttp for async HTTP calls.
        For now, we prepare the payloads and record delivery attempts.
        """
        results = []

        with self._lock:
            matching = [
                wh for wh in self._webhooks.values()
                if wh.enabled
                and (user_id is None or wh.user_id == user_id)
                and any(e.value == event_type for e in wh.events)
            ]

        for wh in matching:
            # Format payload per platform
            formatter = {
                WebhookPlatform.SLACK: self._format_slack_payload,
                WebhookPlatform.DISCORD: self._format_discord_payload,
                WebhookPlatform.TEAMS: self._format_teams_payload,
                WebhookPlatform.GENERIC: self._format_generic_payload,
            }
            payload = formatter[wh.platform](event_type, data)

            with self._lock:
                self._delivery_counter += 1
                delivery = WebhookDelivery(
                    delivery_id=f"del_{self._delivery_counter}",
                    webhook_id=wh.webhook_id,
                    event_type=WebhookEventType(event_type),
                    payload=payload,
                    status="pending",
                )
                self._deliveries.append(delivery)
                results.append({
                    "delivery_id": delivery.delivery_id,
                    "webhook_id": wh.webhook_id,
                    "platform": wh.platform.value,
                    "status": "pending",
                    "payload_preview": json.dumps(payload)[:200],
                })

        return results

    def get_delivery_history(
        self,
        user_id: str,
        limit: int = 50,
    ) -> List[Dict]:
        """Get webhook delivery history for a user."""
        with self._lock:
            user_webhook_ids = {
                wh.webhook_id for wh in self._webhooks.values()
                if wh.user_id == user_id
            }
            deliveries = [
                d for d in self._deliveries
                if d.webhook_id in user_webhook_ids
            ]
            return [
                {
                    "delivery_id": d.delivery_id,
                    "webhook_id": d.webhook_id,
                    "event_type": d.event_type.value,
                    "status": d.status,
                    "response_code": d.response_code,
                    "error": d.error,
                    "timestamp": d.timestamp,
                    "retry_count": d.retry_count,
                }
                for d in deliveries[-limit:]
            ][::-1]

    def get_supported_events(self) -> List[Dict]:
        """Get list of all supported webhook event types."""
        return [
            {"event": e.value, "description": e.value.replace(".", " ").replace("_", " ").title()}
            for e in WebhookEventType
        ]

    def get_supported_platforms(self) -> List[Dict]:
        """Get list of supported webhook platforms."""
        return [
            {"platform": "slack", "name": "Slack", "docs": "https://api.slack.com/messaging/webhooks"},
            {"platform": "discord", "name": "Discord", "docs": "https://discord.com/developers/docs/resources/webhook"},
            {"platform": "teams", "name": "Microsoft Teams", "docs": "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"},
            {"platform": "generic", "name": "Generic (Custom)", "docs": None},
        ]


# Global instance
webhook_service = WebhookIntegrationService()
