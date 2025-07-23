"""
Test suite for the Leaking Agent Detection System
"""
import unittest
import sys
import os
import json

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from email_filtering.email_classifier import EmailClassifier
from behavioral_analysis.user_behavior_analyzer import UserBehaviorAnalyzer
from data_processing.email_processor import EmailProcessor
from utils.config_manager import ConfigManager

class TestEmailClassifier(unittest.TestCase):
    """Test email classification functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ConfigManager()
        self.classifier = EmailClassifier(self.config)

        # Load sample data
        with open('data/sample/sample_emails.json', 'r') as f:
            self.sample_emails = json.load(f)

    def test_spam_detection(self):
        """Test spam email detection"""
        spam_email = next(email for email in self.sample_emails if email['type'] == 'spam')

        result = self.classifier.classify({
            'content': spam_email['content'],
            'headers': spam_email['headers']
        })

        self.assertIsNotNone(result)
        self.assertIn('risk_score', result)
        self.assertGreater(result['risk_score'], 50)  # Should detect as risky

    def test_legitimate_email(self):
        """Test legitimate email classification"""
        legit_email = next(email for email in self.sample_emails if email['type'] == 'legitimate')

        result = self.classifier.classify({
            'content': legit_email['content'],
            'headers': legit_email['headers']
        })

        self.assertIsNotNone(result)
        self.assertIn('risk_score', result)
        # Legitimate emails should have lower risk scores
        self.assertLess(result['risk_score'], 70)

class TestBehavioralAnalyzer(unittest.TestCase):
    """Test behavioral analysis functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ConfigManager()
        self.analyzer = UserBehaviorAnalyzer(self.config)

    def test_after_hours_detection(self):
        """Test after-hours activity detection"""
        user_info = {'user_id': 'test_user'}
        email_data = {
            'content': 'Test email content',
            'attachments': []
        }

        result = self.analyzer.analyze_user_behavior(user_info, email_data)

        self.assertIsNotNone(result)
        self.assertIn('risk_score', result)
        self.assertIn('anomalies_detected', result)

    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        anomalies = {
            'time_anomaly': {'score': 80, 'severity': 'high'},
            'volume_anomaly': {'score': 20, 'severity': 'low'},
            'access_pattern_anomaly': {'score': 40, 'severity': 'medium'},
            'data_movement_anomaly': {'score': 60, 'severity': 'medium'}
        }

        risk_score = self.analyzer._calculate_behavioral_risk_score(anomalies)

        self.assertIsInstance(risk_score, (int, float))
        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 100)

class TestEmailProcessor(unittest.TestCase):
    """Test email processing functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = ConfigManager()
        self.processor = EmailProcessor(self.config)

    def test_email_parsing(self):
        """Test email parsing"""
        raw_email = """From: test@example.com
To: user@company.com
Subject: Test Email

This is a test email content.
"""

        result = self.processor.process_email(raw_email)

        self.assertIsNotNone(result)
        self.assertIn('parsed_email', result)
        self.assertIn('features', result)

    def test_feature_extraction(self):
        """Test feature extraction"""
        sample_email = {
            'content': 'This is a test email with some content!',
            'headers': {'from': 'test@example.com'},
            'attachments': []
        }

        features = self.processor._extract_email_features(sample_email)

        self.assertIsInstance(features, dict)
        self.assertIn('content_length', features)
        self.assertIn('word_count', features)
        self.assertIn('exclamation_count', features)

class TestIntegration(unittest.TestCase):
    """Integration tests"""

    def test_full_email_analysis_pipeline(self):
        """Test complete email analysis pipeline"""
        config = ConfigManager()
        processor = EmailProcessor(config)
        classifier = EmailClassifier(config)

        sample_email = """From: suspicious@example.com
To: user@company.com
Subject: Urgent Action Required!

Click here immediately to verify your account: http://suspicious-link.com
"""

        # Process email
        processed = processor.process_email(sample_email)
        self.assertIsNotNone(processed)

        # Classify email
        classification = classifier.classify(processed['parsed_email'])
        self.assertIsNotNone(classification)
        self.assertIn('risk_score', classification)

def run_tests():
    """Run all tests"""
    # Create test suite
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTest(unittest.makeSuite(TestEmailClassifier))
    suite.addTest(unittest.makeSuite(TestBehavioralAnalyzer))
    suite.addTest(unittest.makeSuite(TestEmailProcessor))
    suite.addTest(unittest.makeSuite(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()

if __name__ == '__main__':
    # Change to project directory
    os.chdir(os.path.join(os.path.dirname(__file__), '..'))

    success = run_tests()
    sys.exit(0 if success else 1)
