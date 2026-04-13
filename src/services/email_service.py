"""
DevPulse - Email Service
Send verification emails, notifications, and reports
"""

import os
import logging
from typing import List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger(__name__)


class EmailService:
    """Email service using SMTP or SendGrid"""
    
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "noreply@devpulse.io")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("FROM_EMAIL", "noreply@devpulse.io")
        self.from_name = os.getenv("FROM_NAME", "DevPulse")
        
        # SendGrid alternative
        self.sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
        
        self.use_sendgrid = bool(self.sendgrid_api_key)

    def send_verification_email(self, email: str, name: str, verification_token: str) -> bool:
        """Send email verification link"""
        verification_url = f"https://devpulse.io/verify?token={verification_token}"
        
        subject = "Verify Your DevPulse Account"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px;">
                    <h2 style="color: #333;">Welcome to DevPulse, {name}!</h2>
                    <p style="color: #666; font-size: 16px;">
                        Thank you for signing up. Please verify your email address by clicking the button below:
                    </p>
                    <a href="{verification_url}" style="display: inline-block; background-color: #007acc; color: white; padding: 12px 30px; border-radius: 4px; text-decoration: none; font-weight: bold; margin: 20px 0;">
                        Verify Email Address
                    </a>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">
                        Or copy and paste this link: {verification_url}
                    </p>
                    <p style="color: #999; font-size: 12px;">
                        This link will expire in 24 hours.
                    </p>
                </div>
            </body>
        </html>
        """
        
        text_body = f"""
        Welcome to DevPulse, {name}!
        
        Please verify your email address by visiting this link:
        {verification_url}
        
        This link will expire in 24 hours.
        """
        
        return self._send_email(email, subject, html_body, text_body)

    def send_password_reset_email(self, email: str, reset_link: str = None, name: str = None, reset_token: str = None) -> bool:
        """Send password reset email.
        Accepts reset_link (full URL, used by main.py) or legacy reset_token.
        """
        reset_url = reset_link or (
            f"https://devpulse.io/reset-password?token={reset_token}" if reset_token else "#"
        )
        
        subject = "Reset Your DevPulse Password"
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px;">
                    <h2 style="color: #333;">Password Reset Request</h2>
                    <p style="color: #666; font-size: 16px;">
                        We received a request to reset your DevPulse password. Click the button below to proceed:
                    </p>
                    <a href="{reset_url}" style="display: inline-block; background-color: #007acc; color: white; padding: 12px 30px; border-radius: 4px; text-decoration: none; font-weight: bold; margin: 20px 0;">
                        Reset Password
                    </a>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">
                        This link will expire in 1 hour. If you didn't request this, please ignore this email.
                    </p>
                </div>
            </body>
        </html>
        """
        
        text_body = f"""
        Password Reset Request
        
        Click this link to reset your password:
        {reset_url}
        
        This link will expire in 1 hour.
        """
        
        return self._send_email(email, subject, html_body, text_body)

    def send_security_alert(self, email: str, name: str, alert_type: str, details: dict) -> bool:
        """Send security alert email"""
        subject = f"Security Alert: {alert_type}"
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px; border-left: 4px solid #d32f2f;">
                    <h2 style="color: #d32f2f;">🚨 Security Alert</h2>
                    <p style="color: #666; font-size: 16px;">
                        Hi {name}, we detected a security issue in your account:
                    </p>
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0;">
                        <p style="color: #333; margin: 0;"><strong>{alert_type}</strong></p>
                        <p style="color: #666; margin: 10px 0 0 0;">{details.get('description', '')}</p>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        <strong>Recommended Action:</strong> {details.get('action', 'Please review your account settings')}
                    </p>
                    <a href="https://devpulse.io/dashboard" style="display: inline-block; background-color: #d32f2f; color: white; padding: 10px 20px; border-radius: 4px; text-decoration: none; font-weight: bold; margin: 20px 0;">
                        Review Account
                    </a>
                </div>
            </body>
        </html>
        """
        
        text_body = f"""
        Security Alert: {alert_type}
        
        Hi {name}, we detected a security issue:
        {details.get('description', '')}
        
        Recommended action: {details.get('action', 'Review your account')}
        """
        
        return self._send_email(email, subject, html_body, text_body)

    def send_compliance_report(self, email: str, name: str, report_type: str, compliance_score: float, file_path: Optional[str] = None) -> bool:
        """Send compliance report email"""
        subject = f"Your {report_type.upper()} Compliance Report"
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px;">
                    <h2 style="color: #333;">Compliance Report: {report_type.upper()}</h2>
                    <p style="color: #666; font-size: 16px;">
                        Hi {name}, your latest {report_type} compliance report is ready.
                    </p>
                    <div style="background-color: #e8f5e9; padding: 20px; border-radius: 4px; margin: 20px 0; text-align: center;">
                        <p style="color: #666; margin: 0; font-size: 14px;">Compliance Score</p>
                        <p style="color: #388e3c; font-size: 36px; font-weight: bold; margin: 10px 0;">{compliance_score:.1f}%</p>
                    </div>
                    <a href="https://devpulse.io/reports" style="display: inline-block; background-color: #007acc; color: white; padding: 12px 30px; border-radius: 4px; text-decoration: none; font-weight: bold; margin: 20px 0;">
                        View Full Report
                    </a>
                </div>
            </body>
        </html>
        """
        
        text_body = f"""
        Compliance Report: {report_type.upper()}
        
        Hi {name}, your latest compliance report is ready.
        
        Compliance Score: {compliance_score:.1f}%
        
        View the full report at: https://devpulse.io/reports
        """
        
        return self._send_email(email, subject, html_body, text_body)

    def send_scan_results(self, email: str, name: str, collection_name: str, risk_score: float, total_findings: int) -> bool:
        """Send scan results summary"""
        subject = f"Scan Complete: {collection_name}"
        
        risk_level = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM" if risk_score >= 40 else "LOW"
        risk_color = "#d32f2f" if risk_level == "CRITICAL" else "#f57c00" if risk_level == "HIGH" else "#fbc02d" if risk_level == "MEDIUM" else "#388e3c"
        
        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; padding: 30px;">
                    <h2 style="color: #333;">Scan Complete: {collection_name}</h2>
                    <div style="background-color: #f9f9f9; padding: 20px; border-radius: 4px; margin: 20px 0;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                            <div>
                                <p style="color: #999; margin: 0; font-size: 12px;">Risk Score</p>
                                <p style="color: {risk_color}; font-size: 28px; font-weight: bold; margin: 5px 0;">{risk_score:.1f}</p>
                            </div>
                            <div>
                                <p style="color: #999; margin: 0; font-size: 12px;">Risk Level</p>
                                <p style="color: {risk_color}; font-size: 20px; font-weight: bold; margin: 5px 0;">{risk_level}</p>
                            </div>
                            <div>
                                <p style="color: #999; margin: 0; font-size: 12px;">Total Findings</p>
                                <p style="color: #333; font-size: 28px; font-weight: bold; margin: 5px 0;">{total_findings}</p>
                            </div>
                        </div>
                    </div>
                    <a href="https://devpulse.io/dashboard" style="display: inline-block; background-color: #007acc; color: white; padding: 12px 30px; border-radius: 4px; text-decoration: none; font-weight: bold; margin: 20px 0;">
                        View Detailed Results
                    </a>
                </div>
            </body>
        </html>
        """
        
        text_body = f"""
        Scan Complete: {collection_name}
        
        Risk Score: {risk_score:.1f}
        Risk Level: {risk_level}
        Total Findings: {total_findings}
        
        View detailed results at: https://devpulse.io/dashboard
        """
        
        return self._send_email(email, subject, html_body, text_body)

    def _send_email(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Internal method to send email via SMTP or SendGrid"""
        try:
            if self.use_sendgrid:
                return self._send_via_sendgrid(to_email, subject, html_body, text_body)
            else:
                return self._send_via_smtp(to_email, subject, html_body, text_body)
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
            return False

    def _send_via_smtp(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send email via SMTP"""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email
            
            part1 = MIMEText(text_body, "plain")
            part2 = MIMEText(html_body, "html")
            
            msg.attach(part1)
            msg.attach(part2)
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_email, to_email, msg.as_string())
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
        except Exception as e:
            logger.error(f"SMTP error: {str(e)}")
            return False

    def _send_via_sendgrid(self, to_email: str, subject: str, html_body: str, text_body: str) -> bool:
        """Send email via SendGrid API"""
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail, Email, To, Content
            
            sg = sendgrid.SendGridAPIClient(self.sendgrid_api_key)
            
            mail = Mail(
                from_email=Email(self.from_email, self.from_name),
                to_emails=To(to_email),
                subject=subject,
                plain_text_content=text_body,
                html_content=html_body
            )
            
            response = sg.send(mail)
            logger.info(f"Email sent via SendGrid to {to_email} (status: {response.status_code})")
            return response.status_code in [200, 201, 202]
        except Exception as e:
            logger.error(f"SendGrid error: {str(e)}")
            return False


# Global instance
email_service = EmailService()
