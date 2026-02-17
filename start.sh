#!/bin/bash

# Bug Hunting Framework - Startup Script
# This script starts the backend server

set -e

echo "=========================================="
echo "Bug Hunting Framework - Starting Server"
echo "=========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "backend/main.py" ]; then
    echo "❌ Error: backend/main.py not found"
    echo "Please run this script from the project root directory"
    exit 1
fi

# Check Python version
echo "🐍 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Python version: $python_version"
echo ""

# Check if dependencies are installed
echo "📦 Checking dependencies..."
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "⚠️  FastAPI not found. Installing dependencies..."
    pip install -q -r requirements.txt
    echo "✅ Dependencies installed"
else
    echo "✅ Dependencies already installed"
fi
echo ""

# Start the backend server
echo "🚀 Starting backend server..."
echo "   API will be available at: http://localhost:8000"
echo "   Frontend will be available at: http://localhost:8000"
echo "   API Documentation: http://localhost:8000/api/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""
echo "=========================================="

# Start the server
python3 -m backend.main
