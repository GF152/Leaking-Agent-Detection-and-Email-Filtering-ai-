#!/usr/bin/env python3
"""
Leaking Agent Detection and Email Filtering AI System
Main application entry point
"""
import sys
import os
import logging
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from email_filtering.email_classifier import EmailClassifier
from behavioral_analysis.user_behavior_analyzer import UserBehaviorAnalyzer  
from data_processing.email_processor import EmailProcessor
from utils.config_manager import ConfigManager
from utils.logger import setup_logger
from utils.database import DatabaseManager

class LeakingAgentDetectionSystem:
    """Main system class that orchestrates all components"""

    def __init__(self, config_path="config/config.json"):
        """Initialize the system with configuration"""
        self.config = ConfigManager(config_path)
        self.logger = setup_logger()

        # Initialize components
        self.email_classifier = EmailClassifier(self.config)
        self.behavior_analyzer = UserBehaviorAnalyzer(self.config)
        self.email_processor = EmailProcessor(self.config)
        self.db_manager = DatabaseManager(self.config)

        self.logger.info("Leaking Agent Detection System initialized")

    def analyze_email(self, email_content, sender_info=None):
        """Analyze a single email for threats"""
        try:
            # Process email
            processed_email = self.email_processor.process_email(email_content)

            # Classify email for spam/phishing
            classification_result = self.email_classifier.classify(processed_email)

            # Analyze sender behavior if info provided
            behavior_analysis = None
            if sender_info:
                behavior_analysis = self.behavior_analyzer.analyze_user_behavior(
                    sender_info, processed_email
                )

            # Combine results
            result = {
                'timestamp': datetime.now().isoformat(),
                'email_classification': classification_result,
                'behavior_analysis': behavior_analysis,
                'risk_score': self._calculate_risk_score(
                    classification_result, behavior_analysis
                )
            }

            # Log to database
            self.db_manager.log_analysis(result)

            return result

        except Exception as e:
            self.logger.error(f"Error analyzing email: {str(e)}")
            return None

    def _calculate_risk_score(self, email_classification, behavior_analysis):
        """Calculate overall risk score"""
        base_score = email_classification.get('risk_score', 0)

        if behavior_analysis:
            behavior_score = behavior_analysis.get('risk_score', 0)
            # Weighted combination
            return min(100, base_score * 0.6 + behavior_score * 0.4)

        return base_score

    def get_system_stats(self):
        """Get system statistics"""
        return self.db_manager.get_system_statistics()

    def start_real_time_monitoring(self):
        """Start real-time email monitoring"""
        self.logger.info("Starting real-time monitoring...")
        # Implementation for real-time monitoring
        pass

def main():
    """Main entry point"""
    print("🛡️  Leaking Agent Detection & Email Filtering AI System")
    print("=" * 60)

    try:
        system = LeakingAgentDetectionSystem()

        # Example usage
        sample_email = """
        From: suspicious@example.com
        To: employee@company.com
        Subject: Urgent: Update your account information

        Dear Employee,

        Your account will be suspended unless you verify your information immediately.
        Click here: http://suspicious-link.com/verify

        Best regards,
        IT Department
        """

        print("\nAnalyzing sample email...")
        result = system.analyze_email(sample_email, {'user_id': 'test_user'})

        if result:
            print(f"Risk Score: {result['risk_score']:.2f}/100")
            print(f"Classification: {result['email_classification']}")
            print("\nSystem ready for deployment!")

    except Exception as e:
        print(f"Error starting system: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
