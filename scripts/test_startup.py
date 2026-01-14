"""
Test startup to identify issues
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

print("Testing imports...")

try:
    print("1. Importing FastAPI...")
    from fastapi import FastAPI
    print("   ✓ FastAPI OK")
    
    print("2. Importing Config...")
    from security_monitor.utils.config import Config
    print("   ✓ Config OK")
    
    print("3. Importing MongoDB...")
    from security_monitor.database import MongoDBHandler
    config = Config()
    mongodb = MongoDBHandler(uri=config.mongodb_uri, db_name=config.mongodb_database)
    print("   ✓ MongoDB OK")
    
    print("4. Importing Auth...")
    from security_monitor.auth import UserStore
    print("   ✓ Auth imports OK")
    
    print("5. Creating UserStore...")
    user_store = UserStore()
    print("   ✓ UserStore created OK")
    
    print("\n✅ All components loaded successfully!")
    print("\nNow testing full dashboard import...")
    
    from security_monitor.dashboard import web_dashboard_secure
    print("\n✅ Dashboard module imported successfully!")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()
