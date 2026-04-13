"""
DevPulse - PDF Report Generator
Generate security and compliance reports in PDF format
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from fpdf import FPDF

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Generate PDF reports for security and compliance"""
    
    def __init__(self, output_dir: str = None):
        if output_dir is None:
            output_dir = os.environ.get("REPORT_OUTPUT_DIR", os.path.join(os.getcwd(), "reports"))
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
            
    def generate_security_report(self, scan_data: Dict[str, Any]) -> str:
        """
        Generate a security scan report PDF
        
        Args:
            scan_data: Data from a security scan
            
        Returns:
            Path to the generated PDF file
        """
        scan_id = scan_data.get("scan_id", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{scan_id}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 24)
        pdf.set_text_color(0, 51, 102)
        pdf.cell(0, 20, "DevPulse Security Report", ln=True, align="C")
        
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Scan ID: {scan_id}", ln=True, align="C")
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", ln=True, align="C")
        
        pdf.ln(10)
        
        # Summary Section
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Summary", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        risk_score = scan_data.get("risk_score", 0.0)
        risk_level = "LOW"
        if risk_score > 70: risk_level = "CRITICAL"
        elif risk_score > 40: risk_level = "HIGH"
        elif risk_score > 20: risk_level = "MEDIUM"
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(50, 10, "Risk Score:", 0)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"{risk_score:.1f}/100", ln=True)
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(50, 10, "Risk Level:", 0)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, risk_level, ln=True)
        
        findings = scan_data.get("findings", [])
        pdf.set_font("Arial", "", 12)
        pdf.cell(50, 10, "Total Findings:", 0)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, str(len(findings)), ln=True)
        
        pdf.ln(10)
        
        # Findings Details
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Findings Details", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        if not findings:
            pdf.set_font("Arial", "I", 12)
            pdf.cell(0, 10, "No vulnerabilities detected.", ln=True)
        else:
            for i, finding in enumerate(findings):
                pdf.set_font("Arial", "B", 12)
                pdf.set_fill_color(240, 240, 240)
                pdf.cell(0, 10, f"{i+1}. {finding.get('title', 'Untitled Finding')}", ln=True, fill=True)
                
                pdf.set_font("Arial", "B", 10)
                severity = finding.get("severity", "info").upper()
                if severity == "CRITICAL": pdf.set_text_color(200, 0, 0)
                elif severity == "HIGH": pdf.set_text_color(255, 100, 0)
                elif severity == "MEDIUM": pdf.set_text_color(200, 150, 0)
                else: pdf.set_text_color(0, 150, 0)
                
                pdf.cell(30, 8, f"Severity: {severity}", ln=True)
                pdf.set_text_color(0, 0, 0)
                
                pdf.set_font("Arial", "", 10)
                pdf.multi_cell(0, 8, f"Description: {finding.get('description', 'No description provided.')}")
                pdf.ln(5)
                
                if pdf.get_y() > 250:
                    pdf.add_page()
        
        # Footer
        pdf.set_y(-15)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, "DevPulse - Secure Your APIs | Page " + str(pdf.page_no()), 0, 0, "C")
        
        pdf.output(filepath)
        logger.info(f"Generated security report: {filepath}")
        return filepath

    def generate_compliance_report(self, compliance_data: Dict[str, Any]) -> str:
        """
        Generate a PCI DSS compliance report PDF
        
        Args:
            compliance_data: Data from a compliance audit (supports 'requirements' or 'controls' key)
            
        Returns:
            Path to the generated PDF file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"compliance_report_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", "B", 24)
        pdf.set_text_color(0, 102, 51)
        pdf.cell(0, 20, "PCI DSS Compliance Report", ln=True, align="C")
        
        pdf.set_font("Arial", "", 12)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Standard: PCI DSS v4.0.1", ln=True, align="C")
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", ln=True, align="C")
        
        pdf.ln(10)
        
        # Summary
        pdf.set_font("Arial", "B", 16)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Compliance Summary", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        summary = compliance_data.get("summary", {})
        status = summary.get("status", "NOT COMPLIANT")
        percentage = summary.get("compliance_percentage", 0.0)
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(50, 10, "Overall Status:", 0)
        pdf.set_font("Arial", "B", 12)
        if status == "COMPLIANT": pdf.set_text_color(0, 150, 0)
        else: pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 10, status, ln=True)
        pdf.set_text_color(0, 0, 0)
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(50, 10, "Compliance %:", 0)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"{percentage:.1f}%", ln=True)
        
        pdf.ln(10)
        
        # Controls/Requirements
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Control Assessment", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        # Support both 'requirements' (from pci_compliance.py) and 'controls' (original schema)
        items = compliance_data.get("requirements") or compliance_data.get("controls", [])
        for item in items:
            pdf.set_font("Arial", "B", 11)
            pdf.set_fill_color(245, 245, 245)
            # Support both 'title' (from requirements) and 'name' (from controls)
            name = item.get('title') or item.get('name', 'Unknown Control')
            pdf.cell(0, 8, f"Control {item.get('id')}: {name}", ln=True, fill=True)
            
            pdf.set_font("Arial", "", 10)
            # Support both 'status' == 'COMPLIANT' (from requirements) and 'compliant' boolean (from controls)
            is_compliant = item.get("status") == "COMPLIANT" if "status" in item else item.get("compliant", False)
            status_text = "PASS" if is_compliant else "FAIL"
            
            if status_text == "PASS": pdf.set_text_color(0, 120, 0)
            else: pdf.set_text_color(180, 0, 0)
            
            pdf.cell(30, 6, f"Status: {status_text}", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            pdf.multi_cell(0, 6, f"Description: {item.get('description', 'No description provided.')}")
            pdf.ln(4)
            
            if pdf.get_y() > 260:
                pdf.add_page()
        
        # Footer
        pdf.set_y(-15)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, "DevPulse - PCI DSS Compliance Audit | Page " + str(pdf.page_no()), 0, 0, "C")
        
        pdf.output(filepath)
        logger.info(f"Generated compliance report: {filepath}")
        return filepath

if __name__ == "__main__":
    # Test generation
    gen = PDFReportGenerator()
    
    # Test scan data
    scan_data = {
        "scan_id": "test_scan_001",
        "risk_score": 45.5,
        "findings": [
            {"title": "SQL Injection", "severity": "critical", "description": "Potential SQL injection in login endpoint."},
            {"title": "Broken Auth", "severity": "high", "description": "Missing token validation on sensitive routes."}
        ]
    }
    
    path = gen.generate_security_report(scan_data)
    print(f"Generated security report at: {path}")
    
    # Test compliance data
    compliance_data = {
        "summary": {
            "status": "PARTIALLY COMPLIANT",
            "compliance_percentage": 75.0
        },
        "controls": [
            {"id": "6.4.1", "name": "API Security", "compliant": True, "description": "All public APIs are secured."},
            {"id": "3.2.1", "name": "Data Encryption", "compliant": False, "description": "Sensitive data not encrypted at rest."}
        ]
    }
    
    path = gen.generate_compliance_report(compliance_data)
    print(f"Generated compliance report at: {path}")
