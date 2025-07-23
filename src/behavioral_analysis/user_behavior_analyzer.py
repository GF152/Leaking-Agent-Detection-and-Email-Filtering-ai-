"""
User Behavior Analytics (UBA) Module for Insider Threat Detection
Implements UEBA algorithms to detect anomalous behavior patterns
"""
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import logging
from collections import defaultdict, deque
import json

class UserBehaviorAnalyzer:
    """Advanced behavioral analytics for insider threat detection"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # User behavior baselines (in production, this would be loaded from database)
        self.user_baselines = {}

        # Activity tracking
        self.user_activities = defaultdict(lambda: deque(maxlen=1000))

        # ML models for anomaly detection
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()

        # Risk scoring weights
        self.risk_weights = {
            'time_anomaly': 0.2,
            'volume_anomaly': 0.25,
            'access_pattern_anomaly': 0.2,
            'data_movement_anomaly': 0.35
        }

        # Initialize baseline data
        self._initialize_baselines()

    def _initialize_baselines(self):
        """Initialize user behavior baselines"""
        # Sample baseline data (in production, load from historical data)
        sample_users = ['J.Smith', 'M.Johnson', 'A.Davis', 'R.Wilson']

        for user in sample_users:
            self.user_baselines[user] = {
                'typical_hours': (9, 17),  # 9 AM to 5 PM
                'avg_emails_per_hour': 5.2,
                'avg_data_access_mb': 50.0,
                'common_recipients': ['internal@company.com'],
                'typical_locations': ['192.168.1.0/24'],
                'access_patterns': {
                    'finance_docs': 0.3 if 'Smith' in user else 0.0,
                    'hr_docs': 0.4 if 'Davis' in user else 0.0,
                    'it_systems': 0.8 if 'Johnson' in user else 0.1,
                    'sales_data': 0.6 if 'Wilson' in user else 0.0
                }
            }

    def analyze_user_behavior(self, user_info, email_data):
        """Main method to analyze user behavior for anomalies"""
        try:
            user_id = user_info.get('user_id', 'unknown')

            # Extract behavioral features
            features = self._extract_behavioral_features(user_info, email_data)

            # Detect anomalies
            anomalies = self._detect_anomalies(user_id, features)

            # Calculate risk score
            risk_score = self._calculate_behavioral_risk_score(anomalies)

            # Generate insights
            insights = self._generate_insights(user_id, anomalies, features)

            # Log activity
            self._log_user_activity(user_id, features, risk_score)

            result = {
                'user_id': user_id,
                'risk_score': risk_score,
                'anomalies_detected': anomalies,
                'behavioral_features': features,
                'insights': insights,
                'timestamp': datetime.now().isoformat()
            }

            return result

        except Exception as e:
            self.logger.error(f"Error analyzing user behavior: {e}")
            return {'error': str(e)}

    def _extract_behavioral_features(self, user_info, email_data):
        """Extract behavioral features from user activity"""
        current_time = datetime.now()

        features = {
            # Temporal features
            'hour_of_day': current_time.hour,
            'day_of_week': current_time.weekday(),
            'is_weekend': current_time.weekday() >= 5,
            'is_after_hours': current_time.hour < 8 or current_time.hour > 18,

            # Email features
            'email_length': len(email_data.get('content', '')),
            'has_attachments': len(email_data.get('attachments', [])) > 0,
            'attachment_count': len(email_data.get('attachments', [])),
            'external_recipients': self._count_external_recipients(email_data),

            # Content features
            'urgent_keywords': self._count_urgent_keywords(email_data.get('content', '')),
            'financial_keywords': self._count_financial_keywords(email_data.get('content', '')),
            'confidential_keywords': self._count_confidential_keywords(email_data.get('content', '')),

            # Network features (simulated)
            'ip_location_risk': self._assess_ip_location_risk(user_info.get('ip_address')),
            'connection_type': user_info.get('connection_type', 'internal'),

            # Access patterns (simulated)
            'data_access_volume': np.random.normal(50, 15),  # MB
            'system_access_count': np.random.poisson(10),
            'privilege_level': user_info.get('privilege_level', 'user')
        }

        return features

    def _detect_anomalies(self, user_id, features):
        """Detect various types of behavioral anomalies"""
        anomalies = {}
        baseline = self.user_baselines.get(user_id, {})

        # Time-based anomalies
        anomalies['time_anomaly'] = self._detect_time_anomaly(features, baseline)

        # Volume anomalies
        anomalies['volume_anomaly'] = self._detect_volume_anomaly(features, baseline)

        # Access pattern anomalies
        anomalies['access_pattern_anomaly'] = self._detect_access_pattern_anomaly(features, baseline)

        # Data movement anomalies
        anomalies['data_movement_anomaly'] = self._detect_data_movement_anomaly(features, baseline)

        return anomalies

    def _detect_time_anomaly(self, features, baseline):
        """Detect time-based anomalies"""
        score = 0
        details = []

        if features['is_after_hours']:
            score += 40
            details.append("Activity during after-hours")

        if features['is_weekend']:
            score += 30
            details.append("Activity during weekend")

        # Check if activity is outside typical hours
        typical_hours = baseline.get('typical_hours', (9, 17))
        if features['hour_of_day'] < typical_hours[0] or features['hour_of_day'] > typical_hours[1]:
            score += 25
            details.append(f"Activity outside typical hours ({typical_hours[0]}:00-{typical_hours[1]}:00)")

        return {
            'score': min(100, score),
            'details': details,
            'severity': 'high' if score > 70 else 'medium' if score > 40 else 'low'
        }

    def _detect_volume_anomaly(self, features, baseline):
        """Detect volume-based anomalies"""
        score = 0
        details = []

        baseline_data_access = baseline.get('avg_data_access_mb', 50.0)
        current_access = features['data_access_volume']

        # Check for unusually high data access
        if current_access > baseline_data_access * 3:
            score += 60
            details.append(f"Data access volume {current_access:.1f}MB is {current_access/baseline_data_access:.1f}x normal")
        elif current_access > baseline_data_access * 2:
            score += 35
            details.append(f"Elevated data access volume detected")

        # Check for unusual attachment behavior
        if features['attachment_count'] > 5:
            score += 25
            details.append(f"High number of attachments ({features['attachment_count']})")

        return {
            'score': min(100, score),
            'details': details,
            'severity': 'high' if score > 70 else 'medium' if score > 40 else 'low'
        }

    def _detect_access_pattern_anomaly(self, features, baseline):
        """Detect access pattern anomalies"""
        score = 0
        details = []

        # Check for privilege escalation indicators
        if features['privilege_level'] == 'admin' and features['is_after_hours']:
            score += 50
            details.append("Administrative access during after-hours")

        # Check for unusual system access patterns
        if features['system_access_count'] > 20:
            score += 30
            details.append("High system access frequency")

        # Check for external connection risks
        if features['connection_type'] == 'vpn' and features['is_weekend']:
            score += 25
            details.append("VPN access during weekend")

        return {
            'score': min(100, score),
            'details': details,
            'severity': 'high' if score > 70 else 'medium' if score > 40 else 'low'
        }

    def _detect_data_movement_anomaly(self, features, baseline):
        """Detect data exfiltration patterns"""
        score = 0
        details = []

        # Check for external recipients
        if features['external_recipients'] > 0:
            score += 40
            details.append(f"Email sent to {features['external_recipients']} external recipients")

        # Check for suspicious content indicators
        if features['confidential_keywords'] > 0:
            score += 35
            details.append("Confidential content detected in email")

        if features['financial_keywords'] > 0:
            score += 30
            details.append("Financial information detected in email")

        # Check for large attachments
        if features['has_attachments'] and features['attachment_count'] > 3:
            score += 25
            details.append("Multiple attachments may indicate data collection")

        return {
            'score': min(100, score),
            'details': details,
            'severity': 'high' if score > 70 else 'medium' if score > 40 else 'low'
        }

    def _calculate_behavioral_risk_score(self, anomalies):
        """Calculate overall behavioral risk score"""
        weighted_score = 0

        for anomaly_type, weight in self.risk_weights.items():
            if anomaly_type in anomalies:
                weighted_score += anomalies[anomaly_type]['score'] * weight

        return min(100, weighted_score)

    def _generate_insights(self, user_id, anomalies, features):
        """Generate actionable insights based on detected anomalies"""
        insights = []
        high_risk_anomalies = []

        for anomaly_type, data in anomalies.items():
            if data['severity'] == 'high':
                high_risk_anomalies.append(anomaly_type)
                insights.extend(data['details'])

        # Generate recommendations
        recommendations = []
        if high_risk_anomalies:
            recommendations.append(f"Immediate review recommended for user {user_id}")
            recommendations.append("Consider temporarily restricting user privileges")
            recommendations.append("Schedule interview with user's manager")

        return {
            'risk_indicators': insights,
            'recommendations': recommendations,
            'high_risk_categories': high_risk_anomalies
        }

    def _log_user_activity(self, user_id, features, risk_score):
        """Log user activity for historical analysis"""
        activity_record = {
            'timestamp': datetime.now().isoformat(),
            'features': features,
            'risk_score': risk_score
        }

        self.user_activities[user_id].append(activity_record)

    def _count_external_recipients(self, email_data):
        """Count external email recipients"""
        recipients = email_data.get('recipients', [])
        external_count = 0

        for recipient in recipients:
            if '@company.com' not in recipient.lower():
                external_count += 1

        return external_count

    def _count_urgent_keywords(self, content):
        """Count urgent/pressure keywords"""
        urgent_keywords = ['urgent', 'immediate', 'asap', 'emergency', 'critical', 'deadline']
        content_lower = content.lower()
        return sum(1 for keyword in urgent_keywords if keyword in content_lower)

    def _count_financial_keywords(self, content):
        """Count financial-related keywords"""
        financial_keywords = ['bank', 'account', 'payment', 'transfer', 'money', 'salary', 'bonus']
        content_lower = content.lower()
        return sum(1 for keyword in financial_keywords if keyword in content_lower)

    def _count_confidential_keywords(self, content):
        """Count confidential/sensitive keywords"""
        confidential_keywords = ['confidential', 'secret', 'proprietary', 'internal', 'private', 'classified']
        content_lower = content.lower()
        return sum(1 for keyword in confidential_keywords if keyword in content_lower)

    def _assess_ip_location_risk(self, ip_address):
        """Assess risk based on IP location (simplified)"""
        if not ip_address:
            return 0

        # Simple risk assessment based on IP patterns
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return 0  # Internal network
        elif ip_address.startswith('172.'):
            return 10  # Private network
        else:
            return 30  # External IP

    def get_user_risk_profile(self, user_id):
        """Get comprehensive risk profile for a user"""
        activities = list(self.user_activities.get(user_id, []))

        if not activities:
            return {'error': 'No activity data available'}

        # Calculate statistics
        risk_scores = [activity['risk_score'] for activity in activities[-30:]]  # Last 30 activities

        profile = {
            'user_id': user_id,
            'current_risk_score': risk_scores[-1] if risk_scores else 0,
            'average_risk_score': np.mean(risk_scores) if risk_scores else 0,
            'max_risk_score': max(risk_scores) if risk_scores else 0,
            'risk_trend': 'increasing' if len(risk_scores) > 1 and risk_scores[-1] > risk_scores[-2] else 'stable',
            'total_activities': len(activities),
            'high_risk_activities': sum(1 for score in risk_scores if score > 70),
            'last_activity': activities[-1]['timestamp'] if activities else None
        }

        return profile

    def update_baseline(self, user_id, new_data):
        """Update user baseline based on new legitimate activity"""
        if user_id not in self.user_baselines:
            self.user_baselines[user_id] = {}

        # Update baseline with new data (simplified approach)
        baseline = self.user_baselines[user_id]

        # Update typical hours based on activity pattern
        if 'activity_hours' in new_data:
            baseline['typical_hours'] = new_data['activity_hours']

        # Update average data access
        if 'data_access' in new_data:
            current_avg = baseline.get('avg_data_access_mb', 50.0)
            baseline['avg_data_access_mb'] = (current_avg + new_data['data_access']) / 2

        self.logger.info(f"Updated baseline for user {user_id}")
