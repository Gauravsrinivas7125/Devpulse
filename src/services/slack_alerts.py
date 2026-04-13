"""
DevPulse - Slack Alerts Integration
Send real-time notifications for security events and kill switch triggers
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


class SlackAlertsService:
    """Slack integration for DevPulse alerts"""
    
    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook_url)
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        fields: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Send an alert to Slack"""
        if not self.enabled:
            logger.warning("Slack alerts disabled - no webhook URL configured")
            return {"success": False, "error": "Slack not configured"}
        
        try:
            # Color based on severity
            color_map = {
                "critical": "#FF0000",
                "high": "#FF6600",
                "medium": "#FFAA00",
                "low": "#00AA00",
                "info": "#0099FF"
            }
            color = color_map.get(severity, "#0099FF")
            
            # Build Slack message
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "text": message,
                        "ts": int(datetime.utcnow().timestamp()),
                        "fields": [
                            {"title": k, "value": v, "short": True}
                            for k, v in (fields or {}).items()
                        ]
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(self.webhook_url, json=payload)
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent: {title}")
                return {"success": True, "message": "Alert sent"}
            else:
                logger.error(f"Slack alert failed: {response.text}")
                return {"success": False, "error": response.text}
        
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def send_kill_switch_alert(
        self,
        reason: str,
        request_id: str,
        user_id: str,
        blocked_count: int
    ) -> Dict[str, Any]:
        """Send kill switch trigger alert"""
        return self.send_alert(
            title="🚨 AgentGuard™ Kill Switch Triggered",
            message=f"An AI agent loop was detected and blocked automatically.",
            severity="critical",
            fields={
                "Reason": reason,
                "Request ID": request_id,
                "User": user_id,
                "Total Blocked": str(blocked_count),
                "Timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def send_security_finding_alert(
        self,
        finding_type: str,
        severity: str,
        collection_id: str,
        description: str
    ) -> Dict[str, Any]:
        """Send security finding alert"""
        return self.send_alert(
            title=f"🔒 Security Finding: {finding_type}",
            message=description,
            severity=severity,
            fields={
                "Type": finding_type,
                "Severity": severity,
                "Collection": collection_id,
                "Timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def send_compliance_alert(
        self,
        compliance_type: str,
        status: str,
        percentage: float,
        collection_id: str
    ) -> Dict[str, Any]:
        """Send compliance status alert"""
        return self.send_alert(
            title=f"📋 {compliance_type} Compliance Report",
            message=f"Compliance status: {status} ({percentage}%)",
            severity="info" if percentage >= 80 else "medium",
            fields={
                "Compliance Type": compliance_type,
                "Status": status,
                "Percentage": f"{percentage}%",
                "Collection": collection_id,
                "Timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def send_billing_alert(
        self,
        event_type: str,
        user_id: str,
        amount: Optional[float] = None,
        tier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Send billing event alert"""
        return self.send_alert(
            title=f"💳 Billing Event: {event_type}",
            message=f"A billing event occurred for user {user_id}",
            severity="info",
            fields={
                "Event": event_type,
                "User": user_id,
                "Amount": f"${amount}" if amount else "N/A",
                "Tier": tier or "N/A",
                "Timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def send_system_alert(
        self,
        alert_type: str,
        message: str,
        severity: str = "medium"
    ) -> Dict[str, Any]:
        """Send system-level alert"""
        return self.send_alert(
            title=f"⚙️ System Alert: {alert_type}",
            message=message,
            severity=severity,
            fields={
                "Type": alert_type,
                "Timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def send_investor_demo_alert(
        self,
        demo_type: str,
        user_id: str,
        details: str
    ) -> Dict[str, Any]:
        """Send investor demo moment alert (Kill Switch Trigger 4)"""
        return self.send_alert(
            title="🎯 Investor Demo Moment - AgentGuard™ Kill Switch",
            message=f"The autonomous safety mechanism just saved the day in real-time.",
            severity="critical",
            fields={
                "Demo Type": demo_type,
                "User": user_id,
                "Details": details,
                "Timestamp": datetime.utcnow().isoformat(),
                "Message": "This is the moment that sells the product to investors."
            }
        )


# Global alerts service instance
alerts_service = SlackAlertsService()
