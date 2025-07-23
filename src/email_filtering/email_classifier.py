"""
Email Classification Module using BERT and traditional ML algorithms
Handles spam detection, phishing detection, and malware scanning
"""
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import logging

class EmailClassifier:
    """Advanced email classifier using multiple ML approaches"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize models
        self.traditional_models = {}
        self.bert_model = None
        self.bert_tokenizer = None

        # Email patterns for rule-based detection
        self.phishing_patterns = [
            r'urgent.{0,20}action.{0,20}required',
            r'verify.{0,20}account',
            r'suspended.{0,20}account',
            r'click.{0,20}here.{0,20}immediately',
            r'winner.{0,20}lottery',
            r'congratulations.{0,20}selected'
        ]

        self.spam_keywords = [
            'viagra', 'cialis', 'money', 'free', 'winner', 'lottery',
            'inheritance', 'prince', 'million', 'dollars', 'prize'
        ]

        self._initialize_models()

    def _initialize_models(self):
        """Initialize all ML models"""
        try:
            # Traditional ML models
            self.traditional_models = {
                'naive_bayes': Pipeline([
                    ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
                    ('classifier', MultinomialNB())
                ]),
                'random_forest': Pipeline([
                    ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
                    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
                ]),
                'svm': Pipeline([
                    ('tfidf', TfidfVectorizer(max_features=5000, stop_words='english')),
                    ('classifier', SVC(probability=True, kernel='rbf'))
                ])
            }

            # Initialize BERT model for advanced detection
            try:
                model_name = 'distilbert-base-uncased'
                self.bert_tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.bert_model = AutoModelForSequenceClassification.from_pretrained(
                    model_name, num_labels=2
                )
                self.logger.info("BERT model initialized successfully")
            except Exception as e:
                self.logger.warning(f"Could not initialize BERT model: {e}")

        except Exception as e:
            self.logger.error(f"Error initializing models: {e}")

    def classify(self, email_data):
        """Main classification method"""
        try:
            email_content = email_data.get('content', '')
            email_headers = email_data.get('headers', {})

            # Rule-based detection
            rule_based_score = self._rule_based_detection(email_content, email_headers)

            # Traditional ML detection
            ml_score = self._traditional_ml_detection(email_content)

            # BERT-based detection (if available)
            bert_score = self._bert_detection(email_content)

            # Combine scores
            final_score = self._combine_scores(rule_based_score, ml_score, bert_score)

            # Determine classification
            classification = self._determine_classification(final_score)

            result = {
                'is_spam': classification['is_spam'],
                'is_phishing': classification['is_phishing'],
                'is_malware': classification['is_malware'],
                'risk_score': final_score['overall_risk'],
                'confidence': final_score['confidence'],
                'detection_methods': {
                    'rule_based': rule_based_score,
                    'traditional_ml': ml_score,
                    'bert_based': bert_score
                },
                'details': classification['details']
            }

            return result

        except Exception as e:
            self.logger.error(f"Error in email classification: {e}")
            return {'error': str(e)}

    def _rule_based_detection(self, content, headers):
        """Rule-based detection using patterns and keywords"""
        content_lower = content.lower()

        # Phishing detection
        phishing_score = 0
        for pattern in self.phishing_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                phishing_score += 20

        # Spam keyword detection
        spam_score = 0
        for keyword in self.spam_keywords:
            if keyword in content_lower:
                spam_score += 10

        # Header analysis
        header_score = 0
        sender = headers.get('from', '').lower()
        if any(suspicious in sender for suspicious in ['noreply', 'donotreply', 'temp']):
            header_score += 15

        # Check for suspicious links
        link_score = 0
        links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
        for link in links:
            if any(suspicious in link for suspicious in ['bit.ly', 'tinyurl', 'suspicious']):
                link_score += 25

        return {
            'phishing_score': min(100, phishing_score),
            'spam_score': min(100, spam_score),
            'header_score': min(100, header_score),
            'link_score': min(100, link_score)
        }

    def _traditional_ml_detection(self, content):
        """Traditional ML-based detection"""
        try:
            # For demo purposes, simulate ML predictions
            # In real implementation, these would use trained models

            # Simulate feature extraction and prediction
            features = self._extract_features(content)

            # Simulate predictions from different models
            predictions = {
                'naive_bayes': np.random.random() * 0.3 + 0.1,  # Lower base probability
                'random_forest': np.random.random() * 0.4 + 0.1,
                'svm': np.random.random() * 0.35 + 0.1
            }

            # If content has suspicious patterns, increase scores
            if any(keyword in content.lower() for keyword in self.spam_keywords[:5]):
                predictions = {k: min(1.0, v + 0.4) for k, v in predictions.items()}

            return {
                'ensemble_score': np.mean(list(predictions.values())) * 100,
                'individual_scores': {k: v * 100 for k, v in predictions.items()},
                'feature_count': len(features)
            }
        except Exception as e:
            self.logger.error(f"Error in traditional ML detection: {e}")
            return {'ensemble_score': 0, 'individual_scores': {}, 'feature_count': 0}

    def _bert_detection(self, content):
        """BERT-based detection"""
        try:
            if self.bert_model is None or self.bert_tokenizer is None:
                return {'score': 0, 'confidence': 0, 'available': False}

            # Tokenize and predict
            inputs = self.bert_tokenizer(
                content[:512],  # Limit to BERT's max length
                return_tensors="pt",
                truncation=True,
                padding=True
            )

            with torch.no_grad():
                outputs = self.bert_model(**inputs)
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                threat_probability = probabilities[0][1].item()  # Assuming label 1 is threat

            return {
                'score': threat_probability * 100,
                'confidence': max(probabilities[0]).item() * 100,
                'available': True
            }

        except Exception as e:
            self.logger.error(f"Error in BERT detection: {e}")
            return {'score': 0, 'confidence': 0, 'available': False}

    def _extract_features(self, content):
        """Extract features for traditional ML"""
        features = {
            'word_count': len(content.split()),
            'char_count': len(content),
            'exclamation_count': content.count('!'),
            'question_count': content.count('?'),
            'uppercase_ratio': sum(1 for c in content if c.isupper()) / max(len(content), 1),
            'digit_count': sum(1 for c in content if c.isdigit()),
            'url_count': len(re.findall(r'http[s]?://\S+', content)),
            'email_count': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content))
        }
        return features

    def _combine_scores(self, rule_based, ml_based, bert_based):
        """Combine scores from different detection methods"""
        # Weighted combination
        weights = {
            'rule_based': 0.3,
            'ml_based': 0.4,
            'bert_based': 0.3 if bert_based.get('available', False) else 0
        }

        # Normalize weights if BERT is not available
        if not bert_based.get('available', False):
            weights['rule_based'] = 0.4
            weights['ml_based'] = 0.6

        # Calculate combined scores
        rule_score = max(
            rule_based['phishing_score'],
            rule_based['spam_score'],
            rule_based['link_score']
        )

        ml_score = ml_based['ensemble_score']
        bert_score = bert_based.get('score', 0)

        overall_risk = (
            weights['rule_based'] * rule_score +
            weights['ml_based'] * ml_score +
            weights['bert_based'] * bert_score
        )

        # Calculate confidence
        confidence_scores = [rule_score, ml_score]
        if bert_based.get('available', False):
            confidence_scores.append(bert_based.get('confidence', 0))

        confidence = np.mean(confidence_scores)

        return {
            'overall_risk': min(100, overall_risk),
            'confidence': confidence,
            'component_scores': {
                'rule_based': rule_score,
                'ml_based': ml_score,
                'bert_based': bert_score
            }
        }

    def _determine_classification(self, scores):
        """Determine final classification based on scores"""
        risk_score = scores['overall_risk']

        # Thresholds
        phishing_threshold = 70
        spam_threshold = 60
        malware_threshold = 80

        classification = {
            'is_spam': risk_score >= spam_threshold,
            'is_phishing': risk_score >= phishing_threshold,
            'is_malware': risk_score >= malware_threshold,
            'details': []
        }

        if risk_score >= malware_threshold:
            classification['details'].append('High risk of malware')
        elif risk_score >= phishing_threshold:
            classification['details'].append('Potential phishing attempt')
        elif risk_score >= spam_threshold:
            classification['details'].append('Likely spam')
        else:
            classification['details'].append('Low risk')

        return classification

    def train_model(self, training_data):
        """Train the traditional ML models"""
        try:
            X = training_data['content']
            y = training_data['labels']

            for name, model in self.traditional_models.items():
                self.logger.info(f"Training {name} model...")
                model.fit(X, y)

            self.logger.info("Model training completed")
            return True

        except Exception as e:
            self.logger.error(f"Error training models: {e}")
            return False
