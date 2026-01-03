"""
Email Notification Module
Sends security alert notifications via email
"""

import smtplib
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any


class EmailSender:
    """Sends email notifications for security alerts"""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        sender_email: str,
        sender_password: str,
        recipient_emails: List[str]
    ):
        """
        Initialize email sender
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP server port
            sender_email: Sender email address
            sender_password: Sender email password/app password
            recipient_emails: List of recipient email addresses
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient_emails = recipient_emails
    
    def send_alert(self, alerts: List[Dict[str, Any]], computer: str = 'localhost') -> bool:
        """
        Send email alert for security events
        
        Args:
            alerts: List of alert dictionaries
            computer: Computer name
            
        Returns:
            True if successful, False otherwise
        """
        if not alerts:
            return False
        
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = ', '.join(self.recipient_emails)
            
            # Count severity levels
            high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
            medium_alerts = [a for a in alerts if a.get('severity') == 'MEDIUM']
            
            # Subject line
            if high_alerts:
                msg['Subject'] = f"🚨 CRITICAL: {len(high_alerts)} High Severity Security Alert(s)"
            else:
                msg['Subject'] = f"⚠️ Security Alert: {len(medium_alerts)} Medium Severity Threat(s)"
            
            # Create HTML email body
            html_body = self._create_email_html(alerts, high_alerts, medium_alerts, computer)
            
            # Attach HTML body
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            print(f"✓ Email alert sent to {len(self.recipient_emails)} recipient(s)")
            return True
            
        except smtplib.SMTPAuthenticationError:
            print(f"❌ Email authentication failed - Check credentials")
            return False
        except smtplib.SMTPException as e:
            print(f"❌ SMTP error: {e}")
            return False
        except Exception as e:
            print(f"❌ Failed to send email: {e}")
            return False
    
    def _create_email_html(
        self,
        alerts: List[Dict[str, Any]],
        high_alerts: List[Dict[str, Any]],
        medium_alerts: List[Dict[str, Any]],
        computer: str
    ) -> str:
        """Create HTML email body"""
        
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    padding: 20px;
                }}
                .container {{
                    background-color: white;
                    border-radius: 8px;
                    padding: 20px;
                    max-width: 600px;
                    margin: 0 auto;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .header {{
                    background-color: {'#d32f2f' if high_alerts else '#f57c00'};
                    color: white;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .alert-box {{
                    border-left: 4px solid {'#d32f2f' if high_alerts else '#f57c00'};
                    padding: 15px;
                    margin: 10px 0;
                    background-color: #f9f9f9;
                    border-radius: 4px;
                }}
                .high {{
                    border-left-color: #d32f2f;
                }}
                .medium {{
                    border-left-color: #f57c00;
                }}
                .summary {{
                    background-color: #e3f2fd;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    color: #666;
                    font-size: 12px;
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🚨 Security Alert - Windows Event Monitor</h2>
                    <p><strong>Time:</strong> {current_time}</p>
                </div>
                
                <div class="summary">
                    <h3>Summary</h3>
                    <ul>
                        <li><strong>Total Alerts:</strong> {len(alerts)}</li>
                        <li><strong style="color: #d32f2f;">HIGH Severity:</strong> {len(high_alerts)}</li>
                        <li><strong style="color: #f57c00;">MEDIUM Severity:</strong> {len(medium_alerts)}</li>
                    </ul>
                </div>
                
                <h3>Alert Details</h3>
        """
        
        # Add each alert
        for alert in alerts:
            severity_class = 'high' if alert.get('severity') == 'HIGH' else 'medium'
            color = '#d32f2f' if alert.get('severity') == 'HIGH' else '#f57c00'
            
            html += f"""
                <div class="alert-box {severity_class}">
                    <h4 style="color: {color}; margin-top: 0;">
                        {alert.get('severity', 'UNKNOWN')}: {alert.get('type', 'Unknown Alert')}
                    </h4>
                    <p><strong>Computer:</strong> {alert.get('computer', 'N/A')}</p>
            """
            
            # Add specific details based on alert type
            if alert.get('type') == 'Brute Force Detection':
                html += f"""
                    <p><strong>Failed Attempts:</strong> {alert.get('failed_attempts', 'N/A')}</p>
                    <p><strong>Recent Timestamps:</strong></p>
                    <ul>
                """
                for timestamp in alert.get('timestamps', [])[:3]:
                    html += f"<li>{timestamp}</li>"
                html += "</ul>"
            
            elif 'timestamp' in alert:
                html += f"<p><strong>Time:</strong> {alert['timestamp']}</p>"
            
            if 'note' in alert:
                html += f"<p><strong>Note:</strong> {alert['note']}</p>"
            
            html += "</div>"
        
        html += f"""
                <div class="footer">
                    <p>This is an automated alert from Windows Security Event Monitor.</p>
                    <p>Please investigate these security events immediately.</p>
                    <p>System: {computer}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html