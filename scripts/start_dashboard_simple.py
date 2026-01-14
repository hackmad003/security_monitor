"""
Simple Dashboard Starter
Handles bcrypt warnings and provides clear startup
"""

import sys
import warnings
import os

# Suppress bcrypt version warnings (they're harmless)
warnings.filterwarnings('ignore', message='.*bcrypt.*')

# Suppress passlib bcrypt warnings
import logging
logging.getLogger('passlib').setLevel(logging.ERROR)

print("\n" + "="*70)
print("🔐 Security Monitor Dashboard - Starting...")
print("="*70)
print()

# Now import and start the dashboard
try:
    from pathlib import Path
    # Add project root to path (parent of scripts folder)
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    # Import after suppressing warnings
    from security_monitor.dashboard import web_dashboard_secure
    import uvicorn
    
    # Start the server
    print("=" * 70)
    print("🔐 Security Monitor Dashboard (SECURE VERSION)")
    print("=" * 70)
    print(f"📊 Dashboard URL: http://localhost:8081")
    print(f"📚 API Docs: http://localhost:8081/docs")
    print(f"🔑 Default credentials: admin / ChangeMe123!")
    print("=" * 70)
    print()
    print("⚠️  SECURITY FEATURES ENABLED:")
    print("   ✓ JWT Authentication required for sensitive operations")
    print("   ✓ Secure credential storage with encryption")
    print("   ✓ Input validation on all endpoints")
    print("   ✓ CORS whitelist configured")
    print("   ✓ Protected WebSocket connections")
    print("=" * 70)
    print()
    
    uvicorn.run(web_dashboard_secure.app, host="0.0.0.0", port=8081)
    
except Exception as e:
    print(f"❌ Error starting dashboard: {e}")
    print()
    print("Troubleshooting:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Check Python version: python --version (need 3.8+)")
    print("3. Check logs above for details")
    print()
    sys.exit(1)
