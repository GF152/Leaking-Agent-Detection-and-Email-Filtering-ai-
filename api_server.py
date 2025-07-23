"""
Simple API server for the Leaking Agent Detection System
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from email_filtering.email_classifier import EmailClassifier
from behavioral_analysis.user_behavior_analyzer import UserBehaviorAnalyzer
from data_processing.email_processor import EmailProcessor
from utils.config_manager import ConfigManager
from utils.logger import setup_logger

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize system components
config = ConfigManager()
logger = setup_logger('API')

email_classifier = EmailClassifier(config)
behavior_analyzer = UserBehaviorAnalyzer(config)
email_processor = EmailProcessor(config)

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'system': 'Leaking Agent Detection System',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/analyze/email', methods=['POST'])
def analyze_email():
    """Analyze email endpoint"""
    try:
        data = request.get_json()

        if not data or 'content' not in data:
            return jsonify({'error': 'Email content is required'}), 400

        # Process email
        processed_email = email_processor.process_email(data['content'])

        if 'error' in processed_email:
            return jsonify({'error': processed_email['error']}), 500

        # Classify email
        classification = email_classifier.classify(processed_email['parsed_email'])

        if 'error' in classification:
            return jsonify({'error': classification['error']}), 500

        # Analyze behavior if user info provided
        behavior_analysis = None
        if 'user_info' in data:
            behavior_analysis = behavior_analyzer.analyze_user_behavior(
                data['user_info'], processed_email['parsed_email']
            )

        result = {
            'email_classification': classification,
            'behavior_analysis': behavior_analysis,
            'processed_features': processed_email['features'],
            'timestamp': datetime.now().isoformat()
        }

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/statistics', methods=['GET'])
def get_statistics():
    """Get system statistics"""
    try:
        # Mock statistics for demo
        stats = {
            'emails_processed': 2847293,
            'threats_detected': 8742,
            'insider_risks': 23,
            'system_accuracy': 98.7,
            'uptime': '99.9%',
            'last_updated': datetime.now().isoformat()
        }

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/users/<user_id>/risk', methods=['GET'])
def get_user_risk(user_id):
    """Get user risk profile"""
    try:
        risk_profile = behavior_analyzer.get_user_risk_profile(user_id)
        return jsonify(risk_profile)

    except Exception as e:
        logger.error(f"Error getting user risk profile: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/demo', methods=['GET'])
def demo_endpoint():
    """Demo endpoint with sample analysis"""
    try:
        sample_email = """From: suspicious@phishing-site.com
To: employee@company.com
Subject: URGENT: Your account will be suspended!

Dear Employee,

Your account has been flagged for suspicious activity. 
Click here immediately to verify: http://fake-bank.com/verify

Failure to act within 24 hours will result in permanent suspension.

IT Security Team
"""

        # Process and analyze
        processed = email_processor.process_email(sample_email)
        classification = email_classifier.classify(processed['parsed_email'])

        # Mock behavior analysis
        behavior = behavior_analyzer.analyze_user_behavior(
            {'user_id': 'demo_user'}, 
            processed['parsed_email']
        )

        return jsonify({
            'demo': True,
            'sample_email': sample_email,
            'classification': classification,
            'behavior_analysis': behavior,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error in demo: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("🛡️  Starting Leaking Agent Detection API Server")
    print("=" * 50)
    print("API Endpoints:")
    print("  GET  /              - Health check")
    print("  POST /analyze/email - Analyze email")
    print("  GET  /statistics    - System statistics")
    print("  GET  /users/{id}/risk - User risk profile")
    print("  GET  /demo          - Demo analysis")
    print("\nServer starting on http://localhost:8080")

    app.run(host='0.0.0.0', port=8080, debug=True)
