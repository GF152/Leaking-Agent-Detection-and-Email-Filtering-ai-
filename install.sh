#!/bin/bash
# Installation script for Leaking Agent Detection System

echo "🛡️  Installing Leaking Agent Detection System"
echo "============================================="

# Check Python version
python3 --version
if [ $? -ne 0 ]; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Install requirements
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p data
mkdir -p models

# Initialize database
echo "🗄️  Initializing database..."
python3 -c "
from src.utils.config_manager import ConfigManager
from src.utils.database import DatabaseManager
config = ConfigManager()
db = DatabaseManager(config)
print('Database initialized successfully')
"

# Download NLTK data (if needed)
echo "📚 Downloading NLTK data..."
python3 -c "
import nltk
try:
    nltk.download('punkt')
    nltk.download('stopwords')
    print('NLTK data downloaded successfully')
except:
    print('NLTK data download failed (optional)')
"

echo "✅ Installation completed successfully!"
echo ""
echo "🚀 To start the system:"
echo "   python3 main.py                 # Run main application"
echo "   python3 api_server.py           # Run API server"
echo "   python3 tests/test_system.py    # Run tests"
echo ""
echo "🌐 Web Dashboard: http://localhost:8080"
echo "📖 Documentation: See README.md"
