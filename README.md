# Bug Hunting Framework

A production-grade security testing framework based on human-reasoning methodology with multi-signal vulnerability validation.

## 🚀 Quick Start

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Starting the Application

**Option 1: Using the startup script (Recommended)**
```bash
./start.sh
```

**Option 2: Manual startup**
```bash
# Install dependencies
pip install -r requirements.txt

# Start the backend server
python3 -m backend.main
```

The application will start on `http://localhost:8000`

### Accessing the Interface

Once the server is running:
- **Main Dashboard**: http://localhost:8000
- **Production Scan Demo**: http://localhost:8000/pages/scan-demo.html
- **API Documentation**: http://localhost:8000/api/docs
- **Health Check**: http://localhost:8000/api/health

## 📋 Features

- **Production-Grade Scanning**: Real vulnerability detection with no simulation
- **Multi-Signal Validation**: 4 independent detection signals
- **Statistical Baseline**: 15+ sample analysis with mean/stddev calculations
- **Reproducibility**: 3x confirmation requirement
- **False Positive Suppression**: Automatic filtering of unreliable findings
- **Real-Time Progress**: Live updates during scan execution

## 🔍 How to Use

1. **Start the server** using `./start.sh`
2. **Verify the system is online** - You should see "System Online" in the top-right corner
3. **Navigate to the scan page** - Click on "Production Scan Demo" or go to `/pages/scan-demo.html`
4. **Enter target URL** - Example: `http://testphp.vulnweb.com/`
5. **Specify parameters** - Example: `artist,name,cat`
6. **Click "Start Production Scan"**
7. **Monitor progress** - Watch real-time logs and phase progression
8. **View results** - See confirmed vulnerabilities and suppressed findings

## 🛠️ Troubleshooting

### "System Offline" Error

If you see "System Offline" in the interface:

1. **Check if the backend is running:**
   ```bash
   curl http://localhost:8000/api/health
   ```
   
2. **If not running, start it:**
   ```bash
   ./start.sh
   ```

3. **Refresh your browser** after the server starts

### Port Already in Use

If port 8000 is already in use:
```bash
# Find and kill the process
lsof -ti:8000 | xargs kill -9

# Or use a different port (edit backend/config.py)
```

### Dependencies Issues

If you encounter import errors:
```bash
pip install --upgrade -r requirements.txt
```

## 📊 Architecture

### 6-Phase Scan Workflow
1. **Intelligence Gathering** - Detect tech stack and security headers
2. **Baseline Profiling** - Collect 15+ samples with statistical analysis
3. **Vulnerability Testing** - Multi-signal detection
4. **Validation** - 3x reproducibility checks
5. **Correlation** - Attack path analysis
6. **Reporting** - Complete results compilation

### Multi-Signal Detection
- **Length Delta**: ±2.0 standard deviations from baseline
- **Hash Delta**: SHA-256 content comparison
- **Timing Anomaly**: ±2.5 standard deviations from baseline
- **Status Code Change**: Deviation from most common code

## 🔐 Security

This framework performs **real security testing**. Always ensure you have:
- ✅ Written authorization before testing
- ✅ Testing scope clearly defined
- ✅ Backup of target system (if applicable)
- ✅ Understanding of legal implications

## 📚 API Endpoints

### Production Scan API
- `POST /api/scan/start` - Start a new scan
- `GET /api/scan/status/{scan_id}` - Get scan progress
- `GET /api/scan/results/{scan_id}` - Get complete results
- `GET /api/scan/list` - List all scans

### Legacy Endpoints
- `POST /api/testing/xss` - XSS testing
- `POST /api/testing/sqli` - SQL injection testing
- `POST /api/baseline/capture` - Baseline capture
- `POST /api/recon/detect` - Technology detection

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please ensure all changes:
- Follow the production-grade standards (no simulation)
- Include proper error handling
- Are tested with real scenarios
- Include documentation updates
