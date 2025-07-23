"""
Email Processing Module
Handles email parsing, preprocessing, and feature extraction
"""
import re
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
import hashlib
import base64
import logging
from datetime import datetime
from urllib.parse import urlparse
import json

class EmailProcessor:
    """Email processing and feature extraction"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Regex patterns for feature extraction
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        self.phone_pattern = re.compile(
            r'\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b'
        )

        # Suspicious domains and keywords
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
            'suspicious-domain.com', 'phishing-site.net'
        ]

        self.phishing_keywords = [
            'verify account', 'suspended', 'urgent action', 'click here',
            'update payment', 'confirm identity', 'security alert'
        ]

    def process_email(self, email_content, email_format='raw'):
        """Main email processing method"""
        try:
            if email_format == 'raw':
                parsed_email = self._parse_raw_email(email_content)
            else:
                parsed_email = self._parse_structured_email(email_content)

            # Extract features
            features = self._extract_email_features(parsed_email)

            # Analyze headers
            header_analysis = self._analyze_headers(parsed_email.get('headers', {}))

            # Analyze content
            content_analysis = self._analyze_content(parsed_email.get('content', ''))

            # Analyze attachments
            attachment_analysis = self._analyze_attachments(parsed_email.get('attachments', []))

            # Analyze URLs
            url_analysis = self._analyze_urls(parsed_email.get('content', ''))

            result = {
                'parsed_email': parsed_email,
                'features': features,
                'header_analysis': header_analysis,
                'content_analysis': content_analysis,
                'attachment_analysis': attachment_analysis,
                'url_analysis': url_analysis,
                'processing_timestamp': datetime.now().isoformat()
            }

            return result

        except Exception as e:
            self.logger.error(f"Error processing email: {e}")
            return {'error': str(e)}

    def _parse_raw_email(self, raw_content):
        """Parse raw email content"""
        try:
            msg = email.message_from_string(raw_content)

            # Extract headers
            headers = {}
            for key, value in msg.items():
                decoded_value = self._decode_header(value)
                headers[key.lower()] = decoded_value

            # Extract body content
            content = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))

                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        content += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(part.get_payload()),
                                'hash': hashlib.md5(part.get_payload(decode=True) or b'').hexdigest()
                            })
            else:
                content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

            return {
                'headers': headers,
                'content': content,
                'attachments': attachments,
                'raw_message': msg
            }

        except Exception as e:
            self.logger.error(f"Error parsing raw email: {e}")
            # Fallback: treat as plain text
            return {
                'headers': {},
                'content': raw_content,
                'attachments': [],
                'raw_message': None
            }

    def _parse_structured_email(self, email_data):
        """Parse structured email data (dict format)"""
        return {
            'headers': email_data.get('headers', {}),
            'content': email_data.get('content', ''),
            'attachments': email_data.get('attachments', []),
            'recipients': email_data.get('recipients', []),
            'raw_message': None
        }

    def _decode_header(self, header_value):
        """Decode email header value"""
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ""

            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part

            return decoded_string
        except Exception:
            return str(header_value)

    def _extract_email_features(self, parsed_email):
        """Extract numerical features from email"""
        content = parsed_email.get('content', '')
        headers = parsed_email.get('headers', {})
        attachments = parsed_email.get('attachments', [])

        features = {
            # Content features
            'content_length': len(content),
            'word_count': len(content.split()),
            'sentence_count': len(re.split(r'[.!?]+', content)),
            'paragraph_count': len([p for p in content.split('\n\n') if p.strip()]),

            # Character analysis
            'uppercase_count': sum(1 for c in content if c.isupper()),
            'lowercase_count': sum(1 for c in content if c.islower()),
            'digit_count': sum(1 for c in content if c.isdigit()),
            'special_char_count': sum(1 for c in content if not c.isalnum() and not c.isspace()),

            # Punctuation analysis
            'exclamation_count': content.count('!'),
            'question_count': content.count('?'),
            'comma_count': content.count(','),
            'period_count': content.count('.'),

            # Email-specific features
            'attachment_count': len(attachments),
            'has_attachments': len(attachments) > 0,
            'total_attachment_size': sum(att.get('size', 0) for att in attachments),

            # Header features
            'header_count': len(headers),
            'has_reply_to': 'reply-to' in headers,
            'has_return_path': 'return-path' in headers,

            # URL and link analysis
            'url_count': len(self.url_pattern.findall(content)),
            'email_address_count': len(self.email_pattern.findall(content)),
            'phone_number_count': len(self.phone_pattern.findall(content)),

            # Timing features
            'processing_hour': datetime.now().hour,
            'processing_day': datetime.now().weekday()
        }

        # Calculate ratios
        if features['content_length'] > 0:
            features['uppercase_ratio'] = features['uppercase_count'] / features['content_length']
            features['digit_ratio'] = features['digit_count'] / features['content_length']
            features['special_char_ratio'] = features['special_char_count'] / features['content_length']
        else:
            features['uppercase_ratio'] = 0
            features['digit_ratio'] = 0
            features['special_char_ratio'] = 0

        return features

    def _analyze_headers(self, headers):
        """Analyze email headers for suspicious patterns"""
        analysis = {
            'spf_status': 'unknown',
            'dkim_status': 'unknown', 
            'dmarc_status': 'unknown',
            'suspicious_patterns': [],
            'routing_analysis': {},
            'authenticity_score': 50  # Default neutral score
        }

        # Check authentication headers
        if 'authentication-results' in headers:
            auth_results = headers['authentication-results'].lower()

            if 'spf=pass' in auth_results:
                analysis['spf_status'] = 'pass'
                analysis['authenticity_score'] += 15
            elif 'spf=fail' in auth_results:
                analysis['spf_status'] = 'fail'
                analysis['authenticity_score'] -= 20
                analysis['suspicious_patterns'].append('SPF validation failed')

            if 'dkim=pass' in auth_results:
                analysis['dkim_status'] = 'pass'
                analysis['authenticity_score'] += 15
            elif 'dkim=fail' in auth_results:
                analysis['dkim_status'] = 'fail'
                analysis['authenticity_score'] -= 15
                analysis['suspicious_patterns'].append('DKIM validation failed')

            if 'dmarc=pass' in auth_results:
                analysis['dmarc_status'] = 'pass'
                analysis['authenticity_score'] += 20
            elif 'dmarc=fail' in auth_results:
                analysis['dmarc_status'] = 'fail'
                analysis['authenticity_score'] -= 25
                analysis['suspicious_patterns'].append('DMARC validation failed')

        # Analyze sender reputation
        sender = headers.get('from', '').lower()
        if any(suspicious in sender for suspicious in ['noreply', 'donotreply', 'no-reply']):
            analysis['suspicious_patterns'].append('Suspicious sender address pattern')
            analysis['authenticity_score'] -= 10

        # Check for suspicious received headers
        received_headers = [v for k, v in headers.items() if k == 'received']
        if len(received_headers) > 10:
            analysis['suspicious_patterns'].append('Unusually long routing path')
            analysis['authenticity_score'] -= 15

        # Analyze message ID
        message_id = headers.get('message-id', '')
        if not message_id or not re.match(r'<.+@.+>', message_id):
            analysis['suspicious_patterns'].append('Missing or malformed Message-ID')
            analysis['authenticity_score'] -= 10

        analysis['authenticity_score'] = max(0, min(100, analysis['authenticity_score']))

        return analysis

    def _analyze_content(self, content):
        """Analyze email content for suspicious patterns"""
        content_lower = content.lower()

        analysis = {
            'phishing_indicators': [],
            'spam_indicators': [],
            'urgency_indicators': [],
            'financial_indicators': [],
            'social_engineering_score': 0
        }

        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                analysis['phishing_indicators'].append(keyword)
                analysis['social_engineering_score'] += 15

        # Check for urgency indicators
        urgency_words = ['urgent', 'immediate', 'asap', 'emergency', 'expires', 'deadline']
        for word in urgency_words:
            if word in content_lower:
                analysis['urgency_indicators'].append(word)
                analysis['social_engineering_score'] += 10

        # Check for financial indicators
        financial_words = ['bank', 'payment', 'credit', 'account', 'money', 'transfer', 'paypal']
        for word in financial_words:
            if word in content_lower:
                analysis['financial_indicators'].append(word)
                analysis['social_engineering_score'] += 8

        # Check for spam indicators
        spam_words = ['free', 'win', 'winner', 'prize', 'lottery', 'millions']
        for word in spam_words:
            if word in content_lower:
                analysis['spam_indicators'].append(word)

        # Check for excessive capitalization
        if content.isupper() and len(content) > 50:
            analysis['spam_indicators'].append('excessive_capitalization')
            analysis['social_engineering_score'] += 12

        # Check for multiple exclamation marks
        if content.count('!') > 3:
            analysis['spam_indicators'].append('excessive_exclamation')
            analysis['social_engineering_score'] += 8

        analysis['social_engineering_score'] = min(100, analysis['social_engineering_score'])

        return analysis

    def _analyze_attachments(self, attachments):
        """Analyze email attachments for threats"""
        analysis = {
            'total_count': len(attachments),
            'total_size': sum(att.get('size', 0) for att in attachments),
            'suspicious_types': [],
            'risk_score': 0
        }

        # Dangerous file extensions
        dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.zip', '.rar'
        ]

        for attachment in attachments:
            filename = attachment.get('filename', '').lower()

            # Check for dangerous extensions
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    analysis['suspicious_types'].append(f"{filename} ({ext})")
                    analysis['risk_score'] += 30

        # Check for unusually large attachments
        for attachment in attachments:
            size = attachment.get('size', 0)
            if size > 10 * 1024 * 1024:  # > 10MB
                analysis['risk_score'] += 20

        analysis['risk_score'] = min(100, analysis['risk_score'])

        return analysis

    def _analyze_urls(self, content):
        """Analyze URLs in email content"""
        urls = self.url_pattern.findall(content)

        analysis = {
            'total_count': len(urls),
            'unique_domains': set(),
            'suspicious_urls': [],
            'shortened_urls': [],
            'risk_score': 0
        }

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                analysis['unique_domains'].add(domain)

                # Check for suspicious domains
                if any(suspicious in domain for suspicious in self.suspicious_domains):
                    analysis['suspicious_urls'].append(url)
                    analysis['risk_score'] += 25

                # Check for URL shorteners
                if domain in ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']:
                    analysis['shortened_urls'].append(url)
                    analysis['risk_score'] += 15

                # Check for IP addresses instead of domains
                if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                    analysis['suspicious_urls'].append(url)
                    analysis['risk_score'] += 20

            except Exception as e:
                self.logger.warning(f"Error parsing URL {url}: {e}")

        analysis['unique_domains'] = list(analysis['unique_domains'])
        analysis['risk_score'] = min(100, analysis['risk_score'])

        return analysis

    def extract_metadata(self, email_data):
        """Extract metadata for forensic analysis"""
        metadata = {
            'message_id': email_data.get('headers', {}).get('message-id', ''),
            'sender': email_data.get('headers', {}).get('from', ''),
            'recipients': email_data.get('headers', {}).get('to', ''),
            'subject': email_data.get('headers', {}).get('subject', ''),
            'date': email_data.get('headers', {}).get('date', ''),
            'content_hash': hashlib.sha256(
                email_data.get('content', '').encode()
            ).hexdigest(),
            'processing_timestamp': datetime.now().isoformat()
        }

        return metadata
