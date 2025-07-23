# API Documentation

## Base URL
```
http://localhost:8080
```

## Endpoints

### Health Check
```
GET /
```
Returns system status and basic information.

**Response:**
```json
{
  "status": "online",
  "system": "Leaking Agent Detection System",
  "version": "1.0.0",
  "timestamp": "2025-07-23T20:06:00.000Z"
}
```

### Analyze Email
```
POST /analyze/email
```
Analyzes an email for threats and suspicious behavior.

**Request Body:**
```json
{
  "content": "Email content here...",
  "user_info": {
    "user_id": "john.doe",
    "ip_address": "192.168.1.100"
  }
}
```

**Response:**
```json
{
  "email_classification": {
    "is_spam": false,
    "is_phishing": true,
    "is_malware": false,
    "risk_score": 75.5,
    "confidence": 92.3
  },
  "behavior_analysis": {
    "user_id": "john.doe",
    "risk_score": 45.2,
    "anomalies_detected": {}
  },
  "timestamp": "2025-07-23T20:06:00.000Z"
}
```

### System Statistics
```
GET /statistics
```
Returns system performance metrics and statistics.

**Response:**
```json
{
  "emails_processed": 2847293,
  "threats_detected": 8742,
  "insider_risks": 23,
  "system_accuracy": 98.7,
  "uptime": "99.9%"
}
```

### User Risk Profile
```
GET /users/{user_id}/risk
```
Gets risk profile for a specific user.

**Response:**
```json
{
  "user_id": "john.doe",
  "current_risk_score": 45.2,
  "average_risk_score": 32.1,
  "risk_trend": "increasing",
  "high_risk_activities": 3
}
```

### Demo Analysis
```
GET /demo
```
Provides a demo analysis with sample data.

## Error Responses

All endpoints may return these error responses:

```json
{
  "error": "Error description"
}
```

**Status Codes:**
- 200: Success
- 400: Bad Request
- 500: Internal Server Error
