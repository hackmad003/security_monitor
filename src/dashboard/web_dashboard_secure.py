"""
FastAPI Web Dashboard for Security Monitor - SECURE VERSION
Provides real-time monitoring with JWT authentication
"""

import sys
import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, WebSocket, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel, Field
import uvicorn

# Add security_monitor to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.config import Config
from src.database import MongoDBHandler
from src.core.multi_target_monitor import MultiTargetMonitor
from src.auth import (
    create_access_token,
    get_current_user,
    authenticate_user,
    UserStore
)
from src.utils.rate_limiter import get_rate_limiter

# Initialize FastAPI app
app = FastAPI(
    title="Security Monitor Dashboard",
    version="2.0.0-secure",
    description="Security Event Monitoring Dashboard with JWT Authentication"
)

# SECURE CORS Configuration
allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:8081,http://127.0.0.1:8081").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # FIXED: Whitelist only trusted origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Global instances
config = Config()
mongodb = MongoDBHandler(uri=config.mongodb_uri, db_name=config.mongodb_database)
user_store = UserStore()
multi_monitor = None
active_websockets: List[WebSocket] = []

# Realtime monitoring state
realtime_monitor_active = False
realtime_monitor_thread = None

# Security
security = HTTPBearer()

# Rate limiter
rate_limiter = get_rate_limiter()


# ==========================================
# RATE LIMITING MIDDLEWARE
# ==========================================

@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    """Apply rate limiting to all requests"""
    # Get client identifier (IP address)
    client_ip = request.client.host if request.client else "unknown"
    
    # Determine endpoint type
    endpoint_type = "default"
    if request.url.path.startswith("/api/auth/login"):
        endpoint_type = "login"
    elif request.method in ["POST", "PUT", "DELETE"] and request.url.path.startswith("/api/"):
        endpoint_type = "api_write"
    elif request.method == "GET" and request.url.path.startswith("/api/"):
        endpoint_type = "api_read"
    
    # Check rate limit
    allowed, retry_after = rate_limiter.is_allowed(client_ip, endpoint_type)
    
    if not allowed:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded. Try again in {retry_after} seconds.",
                "retry_after": retry_after
            },
            headers={"Retry-After": str(retry_after)}
        )
    
    # Add rate limit headers
    response = await call_next(request)
    remaining = rate_limiter.get_remaining(client_ip, endpoint_type)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    
    return response


# ==========================================
# PYDANTIC MODELS FOR REQUEST VALIDATION
# ==========================================
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern="^[a-zA-Z0-9-_.]+$")
    hostname: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8)
    enabled: bool = True


class TargetUpdate(BaseModel):
    name: str
    enabled: Optional[bool] = None
    hostname: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(None, max_length=100)
    password: Optional[str] = Field(None, min_length=8)


class MonitoringParams(BaseModel):
    interval: int = Field(default=30, ge=10, le=3600, description="Interval in seconds")
    events_per_check: int = Field(default=100, ge=1, le=10000)


class DetectorUpdate(BaseModel):
    detector: str = Field(..., pattern="^[a-z_]+$")
    enabled: bool


# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================
@app.post("/api/auth/login")
async def login(request: LoginRequest):
    """
    Authenticate user and return JWT token
    
    This endpoint is public (no authentication required)
    """
    user = authenticate_user(request.username, request.password, user_store)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": user['username'], "roles": user.get('roles', [])}
    )
    
    return JSONResponse(content={
        "access_token": access_token,
        "token_type": "bearer",
        "username": user['username'],
        "roles": user.get('roles', [])
    })


@app.get("/api/auth/me")
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    """Get current authenticated user information"""
    user = user_store.get_user(current_user)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Remove password hash
    user_info = {k: v for k, v in user.items() if k != 'password_hash'}
    
    return JSONResponse(content={
        "success": True,
        "user": user_info
    })


# ==========================================
# DASHBOARD HOME PAGE (PUBLIC)
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Serve the main dashboard HTML"""
    html_file = Path(__file__).parent / "dashboard_secure.html"
    if html_file.exists():
        return html_file.read_text(encoding='utf-8')
    return "<h1>Security Monitor Dashboard</h1><p>Dashboard HTML not found</p>"


# ==========================================
# API ENDPOINTS - ALERTS (READ-ONLY, OPTIONAL AUTH)
# ==========================================
@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 50):
    """Get recent alerts (public read access)"""
    try:
        if mongodb.db is None:
            raise HTTPException(status_code=503, detail="Database not connected")
        alerts_collection = mongodb.db['alerts']
        alerts_cursor = alerts_collection.find().sort('timestamp', -1).limit(limit)
        
        all_alerts = []
        for alert in alerts_cursor:
            alert['_id'] = str(alert['_id'])
            if 'run_id' in alert:
                alert['run_id'] = str(alert['run_id'])
            if 'timestamp' in alert and isinstance(alert['timestamp'], datetime):
                alert['timestamp'] = alert['timestamp'].isoformat()
            
            alert_data = {
                'type': alert.get('alert_type', 'Unknown'),
                'severity': alert.get('severity', 'MEDIUM'),
                'computer': alert.get('computer', 'Unknown'),
                'timestamp': alert.get('timestamp', datetime.now().isoformat()),
                'failed_attempts': alert.get('failed_attempts'),
                'details': alert.get('details', {})
            }
            all_alerts.append(alert_data)
        
        return JSONResponse(content={
            "success": True,
            "count": len(all_alerts),
            "alerts": all_alerts
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/api/stats/summary")
async def get_statistics_summary(days: int = 7):
    """Get summary statistics (public read access)"""
    try:
        stats = mongodb.get_statistics(days=days)
        
        high_alerts = mongodb.query_alerts_by_severity('HIGH', days=days)
        medium_alerts = mongodb.query_alerts_by_severity('MEDIUM', days=days)
        low_alerts = mongodb.query_alerts_by_severity('LOW', days=days)
        
        return JSONResponse(content={
            "success": True,
            "stats": {
                "total_runs": stats.get('total_runs', 0),
                "total_events": stats.get('total_events', 0),
                "total_alerts": stats.get('total_alerts', 0),
                "severity_breakdown": {
                    "HIGH": len(high_alerts),
                    "MEDIUM": len(medium_alerts),
                    "LOW": len(low_alerts)
                },
                "days": days
            }
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - CONFIGURATION (PROTECTED)
# ==========================================
@app.get("/api/config/detectors")
async def get_detector_config(_current_user: str = Depends(get_current_user)):
    """Get current detector configuration (requires authentication)"""
    try:
        return JSONResponse(content={
            "success": True,
            "detectors": {
                "brute_force": {
                    "enabled": config.detector_brute_force_enabled,
                    "threshold": config.brute_force_threshold
                },
                "privilege_escalation": {
                    "enabled": config.detector_privilege_escalation_enabled
                },
                "persistence": {
                    "enabled": config.detector_persistence_enabled
                }
            }
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/config/detectors/update")
async def update_detector_config(
    request: DetectorUpdate,
    _current_user: str = Depends(get_current_user)
):
    """Update detector enabled/disabled status (PROTECTED)"""
    try:
        import yaml

        settings_path = Path(__file__).parent / "config" / "app" / "settings.yaml"
        with open(settings_path, 'r') as f:
            settings = yaml.safe_load(f)

        if not isinstance(settings, dict):
            raise HTTPException(status_code=500, detail="Invalid settings format")

        if request.detector in settings.get('detectors', {}):
            settings['detectors'][request.detector]['enabled'] = request.enabled
            
            with open(settings_path, 'w') as f:
                yaml.dump(settings, f, default_flow_style=False, sort_keys=False)
            
            return JSONResponse(content={
                "success": True,
                "message": f"Detector '{request.detector}' {'enabled' if request.enabled else 'disabled'}"
            })
        else:
            raise HTTPException(status_code=404, detail=f"Detector '{request.detector}' not found")
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - MONITORING (PROTECTED)
# ==========================================
@app.get("/api/monitor/status")
async def get_monitor_status(_current_user: str = Depends(get_current_user)):
    """Get realtime monitoring status (PROTECTED)"""
    global realtime_monitor_active, realtime_monitor_thread
    
    is_alive = False
    if realtime_monitor_thread is not None:
        is_alive = realtime_monitor_thread.is_alive()
    
    return JSONResponse(content={
        "success": True,
        "realtime_active": realtime_monitor_active and is_alive,
        "thread_alive": is_alive
    })


@app.post("/api/monitor/start")
async def start_realtime_monitoring(
    params: MonitoringParams,
    _current_user: str = Depends(get_current_user)
):
    """Start realtime monitoring (PROTECTED)"""
    global realtime_monitor_active, realtime_monitor_thread, multi_monitor
    
    try:
        if realtime_monitor_active and realtime_monitor_thread and realtime_monitor_thread.is_alive():
            return JSONResponse(content={
                "success": False,
                "message": "Realtime monitoring is already running"
            }, status_code=400)
        
        if multi_monitor is None:
            multi_monitor = MultiTargetMonitor(config)

        # Capture the monitor locally for the closure
        monitor = multi_monitor

        import threading

        def run_realtime_monitoring():
            global realtime_monitor_active
            try:
                monitor.start_realtime_monitoring(
                    interval_seconds=params.interval
                )
            except Exception as e:
                print(f"Realtime monitoring error: {e}")
                realtime_monitor_active = False
        
        realtime_monitor_active = True
        realtime_monitor_thread = threading.Thread(target=run_realtime_monitoring, daemon=True)
        realtime_monitor_thread.start()
        
        return JSONResponse(content={
            "success": True,
            "message": f"Realtime monitoring started (interval: {params.interval}s)"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/monitor/stop")
async def stop_realtime_monitoring(_current_user: str = Depends(get_current_user)):
    """Stop realtime monitoring (PROTECTED)"""
    global realtime_monitor_active, multi_monitor
    
    try:
        if not realtime_monitor_active:
            return JSONResponse(content={
                "success": False,
                "message": "Realtime monitoring is not running"
            }, status_code=400)
        
        realtime_monitor_active = False
        if multi_monitor:
            multi_monitor.stop_monitoring = True
        
        return JSONResponse(content={
            "success": True,
            "message": "Realtime monitoring stopped"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - TARGET MANAGEMENT (PROTECTED)
# ==========================================
@app.get("/api/targets/list")
async def get_targets(_current_user: str = Depends(get_current_user)):
    """Get list of monitoring targets (PROTECTED)"""
    try:
        import yaml
        
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        if not targets_path.exists():
            return JSONResponse(content={
                "success": True,
                "count": 0,
                "targets": []
            })
        
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)

        if not isinstance(targets_data, dict):
            targets_data = {}

        targets = targets_data.get('targets', [])
        
        # Remove sensitive credentials from response
        safe_targets = []
        for target in targets:
            safe_target = {k: v for k, v in target.items() if k != 'password'}
            if 'credentials' in safe_target:
                safe_target['credentials'] = {
                    'username': safe_target['credentials'].get('username'),
                    'password': '***hidden***'
                }
            safe_targets.append(safe_target)
        
        return JSONResponse(content={
            "success": True,
            "count": len(safe_targets),
            "targets": safe_targets
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/targets/add")
async def add_target(
    request: TargetCreate,
    _current_user: str = Depends(get_current_user)
):
    """Add a new monitoring target (PROTECTED)"""
    try:
        # Store credentials securely
        config.store_target_credentials(request.name, request.username, request.password)
        
        # Store target configuration in targets.yaml (without credentials)
        import yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        if targets_path.exists():
            with open(targets_path, 'r') as f:
                loaded = yaml.safe_load(f)
                targets_data = loaded if isinstance(loaded, dict) else {}
        else:
            targets_data = {}

        if 'targets' not in targets_data:
            targets_data['targets'] = []
        
        # Check if target already exists
        for target in targets_data['targets']:
            if target['name'] == request.name or target['hostname'] == request.hostname:
                return JSONResponse(content={
                    "success": False,
                    "error": f"Target with name '{request.name}' or hostname '{request.hostname}' already exists"
                }, status_code=400)
        
        # Add new target (without credentials)
        new_target = {
            'name': request.name,
            'hostname': request.hostname,
            'enabled': request.enabled
        }
        
        targets_data['targets'].append(new_target)
        
        with open(targets_path, 'w') as f:
            yaml.dump(targets_data, f, default_flow_style=False, sort_keys=False)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Target '{request.name}' added successfully with secure credential storage"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.delete("/api/targets/delete")
async def delete_target(name: str, _current_user: str = Depends(get_current_user)):
    """Delete a target (PROTECTED)"""
    try:
        import yaml
        
        # Delete from targets.yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        with open(targets_path, 'r') as f:
            loaded = yaml.safe_load(f)
            targets_data = loaded if isinstance(loaded, dict) else {}

        original_count = len(targets_data.get('targets', []))
        targets_data['targets'] = [t for t in targets_data.get('targets', []) if t['name'] != name]

        if len(targets_data['targets']) == original_count:
            return JSONResponse(content={
                "success": False,
                "error": f"Target '{name}' not found"
            }, status_code=404)
        
        with open(targets_path, 'w') as f:
            yaml.dump(targets_data, f, default_flow_style=False, sort_keys=False)
        
        # Delete stored credentials
        config.delete_target_credentials(name)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Target '{name}' deleted successfully"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# WEBSOCKET WITH AUTHENTICATION
# ==========================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    """WebSocket endpoint for real-time updates (requires authentication)"""
    # Validate token
    if not token:
        await websocket.close(code=1008, reason="Authentication required")
        return
    
    try:
        # Verify JWT token
        from jose import jwt, JWTError
        SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE-THIS-IN-PRODUCTION-USE-LONG-RANDOM-STRING")
        ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if not username:
            await websocket.close(code=1008, reason="Invalid token")
            return
        
    except JWTError:
        await websocket.close(code=1008, reason="Invalid token")
        return
    
    await websocket.accept()
    active_websockets.append(websocket)
    
    try:
        while True:
            _data = await websocket.receive_text()
            await websocket.send_json({
                "type": "ping",
                "message": "Connected to Security Monitor"
            })
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


# ==========================================
# HEALTH CHECK (PUBLIC)
# ==========================================
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "mongodb_connected": mongodb is not None,
        "version": "2.0.0-secure"
    })


# ==========================================
# STARTUP
# ==========================================
if __name__ == "__main__":
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
    
    uvicorn.run(app, host="0.0.0.0", port=8081)
