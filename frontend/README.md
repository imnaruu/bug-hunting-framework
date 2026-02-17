# Bug Hunter Framework - Frontend

## 🎯 Professional Cybersecurity-Themed Web Interface

A stunning, modern web interface for the Bug Hunting Framework featuring a cyberpunk/hacker terminal aesthetic with neon green accents and professional design.

## ✨ Features

### Design
- **Cyberpunk/Hacker Terminal Aesthetic**
  - Dark backgrounds (#0a0e1a, #111827, #1a1a2e)
  - Neon green primary accent (#00ff88)
  - Neon red/pink alerts (#ff3366)
  - Terminal-style monospace fonts
  - Animated effects and glow shadows
  - Responsive layout for all devices

### Pages

1. **index.html** - Main Dashboard
   - Animated ASCII logo
   - Legal disclaimer banner
   - System status panel
   - Navigation cards to all 6 phases
   - Recent activity feed
   - Statistics cards
   - Quick actions

2. **recon.html** - Reconnaissance & Intelligence
   - Target URL input form
   - Scope verification status
   - Technology detection results
   - Version risk mapping table
   - Risk hypothesis generation
   - Real-time terminal log

3. **baseline.html** - Behavioral Baseline Analysis
   - Response profiling charts
   - Timing baseline graphs
   - Status code distribution
   - Header analysis
   - Cookie security analysis
   - CORS configuration display
   - CSP analysis
   - Error pattern mapping

4. **testing.html** - Interactive Testing Console
   - Decision tree UI for vulnerability testing
   - XSS, SQLi, SSRF, SSTI, CSRF, IDOR testing modules
   - Step-by-step testing flows
   - Payload library with copy functionality
   - Test results terminal
   - Evidence collection forms

5. **correlation.html** - Attack Chain Correlation
   - Attack chain visualization diagrams
   - Finding correlation links
   - Business impact assessment
   - Confidence scoring dashboard
   - Risk matrix
   - Executive summary generation

6. **reports.html** - Report Builder
   - Multiple report templates (Bug Bounty, Pentest, CVE)
   - Auto-populated fields
   - Impact summary editor
   - Step-by-step reproduction
   - Evidence attachment
   - Export options (MD, HTML, PDF)
   - Retest workflow
   - Report history

7. **settings.html** - Settings & Configuration
   - Scope management
   - Authorization documentation upload
   - Platform integrations (HackerOne, Bugcrowd, Burp, ZAP)
   - Notification preferences
   - Theme customization
   - Advanced configuration

## 🚀 Getting Started

### Installation

Simply open any HTML file in a modern web browser. No build process required!

```bash
# Navigate to the frontend directory
cd frontend/pages

# Open in browser (choose your preferred method)
# Option 1: Direct file opening
open index.html  # macOS
start index.html  # Windows
xdg-open index.html  # Linux

# Option 2: Simple HTTP server
python -m http.server 8000
# Then visit: http://localhost:8000/pages/index.html

# Option 3: Using Node.js
npx http-server -p 8000
# Then visit: http://localhost:8000/pages/index.html
```

### File Structure

```
frontend/
├── css/
│   └── style.css          # Main stylesheet with cyberpunk theme
├── js/
│   └── app.js             # Common JavaScript functions
├── pages/
│   ├── index.html         # Main dashboard
│   ├── recon.html         # Reconnaissance phase
│   ├── baseline.html      # Baseline analysis phase
│   ├── testing.html       # Interactive testing phase
│   ├── correlation.html   # Correlation phase
│   ├── reports.html       # Report builder
│   └── settings.html      # Settings & configuration
└── README.md              # This file
```

## 🎨 Design System

### Colors
- **Background Primary**: `#0a0e1a`
- **Background Secondary**: `#111827`
- **Card Background**: `#1a1a2e`
- **Neon Green**: `#00ff88` (Primary accent)
- **Neon Red**: `#ff3366` (Alerts/Critical)
- **Neon Blue**: `#00d4ff` (Info)
- **Text Primary**: `#ffffff`
- **Text Secondary**: `#94a3b8`

### Typography
- **Body Font**: Inter, sans-serif
- **Monospace**: Courier New, Consolas, monospace

### Components
- Cards with hover effects and glow
- Terminal-style output windows
- Decision tree interfaces
- Interactive tabs
- Progress bars
- Status badges
- Animated statistics
- Responsive tables

## 🔧 Customization

### Changing Colors
Edit `css/style.css` and modify the CSS variables:

```css
:root {
    --neon-green: #00ff88;  /* Change primary accent */
    --neon-red: #ff3366;    /* Change alert color */
    --bg-primary: #0a0e1a;  /* Change background */
}
```

### Adding New Pages
1. Copy an existing HTML page as template
2. Update the page title and content
3. Add navigation link in sidebar
4. Include `../css/style.css` and `../js/app.js`

## 📱 Responsive Design

The interface is fully responsive and adapts to:
- Desktop (1920px+)
- Laptop (1280px - 1920px)
- Tablet (768px - 1280px)
- Mobile (< 768px)

On mobile devices, the sidebar collapses and can be toggled.

## 🎯 Key Features

### Interactive Elements
- **Tabs**: Click to switch between content sections
- **Terminal Logs**: Real-time output with color coding
- **Copy Buttons**: One-click payload copying
- **Decision Trees**: Step-by-step guided testing
- **Form Validation**: Client-side validation on all forms

### Animations
- Page load transitions
- Hover effects on cards
- Pulsing status indicators
- Terminal typing cursor
- Number counter animations
- Smooth scrolling

### Accessibility
- Semantic HTML5 elements
- ARIA labels where appropriate
- Keyboard navigation support
- High contrast ratios
- Responsive font sizes

## 🔐 Security Notes

This is a **frontend interface only**. For production use:
- Implement proper backend authentication
- Sanitize all user inputs
- Use HTTPS in production
- Implement CSRF protection
- Add rate limiting
- Validate all data server-side

## 🛠 Browser Support

Tested and working on:
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Opera 76+

## 📄 License

Part of the Bug Hunter Framework project - MIT License

## 🤝 Contributing

Contributions are welcome! Please:
1. Follow the existing code style
2. Maintain the cyberpunk aesthetic
3. Test on multiple browsers
4. Update this README if needed

## 📞 Support

For issues or questions:
- Open an issue on GitHub
- Check the main project documentation
- Review the inline code comments

---

**Created with ❤️ for the security research community**

*Professional. Modern. Stunning.*
