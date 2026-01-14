"""
FastAPI Web Dashboard for Security Monitor
Provides real-time monitoring, historical analysis, and configuration management
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json

from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add security_monitor to path
sys.path.insert(0, str(Path(__file__).parent))

from security_monitor.utils.config import Config
from security_monitor.database import MongoDBHandler, WeeklyJSONExporter
from security_monitor.core.multi_target_monitor import MultiTargetMonitor

# Initialize FastAPI app
app = FastAPI(title="Security Monitor Dashboard", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
config = Config()
mongodb = MongoDBHandler(uri=config.mongodb_uri, db_name=config.mongodb_database)
multi_monitor = None
active_websockets: List[WebSocket] = []

# Realtime monitoring state
realtime_monitor_active = False
realtime_monitor_thread = None


# ==========================================
# DASHBOARD HOME PAGE
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Serve the main dashboard HTML"""
    html_file = Path(__file__).parent / "web" / "dashboard.html"
    if html_file.exists():
        return html_file.read_text(encoding='utf-8')
    return "<h1>Security Monitor Dashboard</h1><p>Dashboard HTML not found</p>"


# ==========================================
# API ENDPOINTS - ALERTS
# ==========================================
@app.get("/api/alerts/recent")
async def get_recent_alerts(limit: int = 50):
    """Get recent alerts"""
    try:
        # Get alerts directly from alerts collection
        alerts_collection = mongodb.db['alerts']
        alerts_cursor = alerts_collection.find().sort('timestamp', -1).limit(limit)
        
        all_alerts = []
        for alert in alerts_cursor:
            # Convert ObjectId and datetime to strings
            alert['_id'] = str(alert['_id'])
            if 'run_id' in alert:
                alert['run_id'] = str(alert['run_id'])
            if 'timestamp' in alert and isinstance(alert['timestamp'], datetime):
                alert['timestamp'] = alert['timestamp'].isoformat()
            
            # Extract details for cleaner display
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


@app.get("/api/alerts/severity/{severity}")
async def get_alerts_by_severity(severity: str, days: int = 7):
    """Get alerts by severity level"""
    try:
        from datetime import timedelta
        
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # Query alerts collection directly
        alerts_collection = mongodb.db['alerts']
        alerts_cursor = alerts_collection.find({
            'severity': severity.upper(),
            'timestamp': {'$gte': cutoff_date}
        }).sort('timestamp', -1)
        
        alerts = []
        for alert in alerts_cursor:
            alert['_id'] = str(alert['_id'])
            if 'run_id' in alert:
                alert['run_id'] = str(alert['run_id'])
            if 'timestamp' in alert and isinstance(alert['timestamp'], datetime):
                alert['timestamp'] = alert['timestamp'].isoformat()
            alerts.append(alert)
        
        return JSONResponse(content={
            "success": True,
            "severity": severity,
            "count": len(alerts),
            "alerts": alerts
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - STATISTICS
# ==========================================
@app.get("/api/stats/summary")
async def get_statistics_summary(days: int = 7):
    """Get summary statistics"""
    try:
        stats = mongodb.get_statistics(days=days)
        
        # Get alert severity breakdown
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


@app.get("/api/stats/timeline")
async def get_timeline_stats(hours: int = 24):
    """Get timeline statistics for charts"""
    try:
        from datetime import timedelta
        
        # Calculate cutoff time
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get alerts from alerts collection
        alerts_collection = mongodb.db['alerts']
        alerts_cursor = alerts_collection.find({
            'timestamp': {'$gte': cutoff_time}
        })
        
        # Group by hour
        timeline = {}
        
        for alert in alerts_cursor:
            timestamp = alert.get('timestamp', datetime.now())
            if isinstance(timestamp, datetime):
                hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                if hour_key not in timeline:
                    timeline[hour_key] = {
                        'events': 0,
                        'alerts': 0,
                        'high_severity': 0
                    }
                
                timeline[hour_key]['alerts'] += 1
                timeline[hour_key]['events'] += 1  # Count each alert as an event
                
                if alert.get('severity') == 'HIGH':
                    timeline[hour_key]['high_severity'] += 1
        
        return JSONResponse(content={
            "success": True,
            "timeline": timeline
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - CONFIGURATION
# ==========================================
@app.get("/api/config/detectors")
async def get_detector_config():
    """Get current detector configuration"""
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
async def update_detector_config(detector: str, enabled: bool):
    """Update detector enabled/disabled status"""
    try:
        import yaml
        
        # Load settings.yaml
        settings_path = Path(__file__).parent / "config" / "app" / "settings.yaml"
        with open(settings_path, 'r') as f:
            settings = yaml.safe_load(f)
        
        # Update detector
        if detector in settings.get('detectors', {}):
            settings['detectors'][detector]['enabled'] = enabled
            
            # Save
            with open(settings_path, 'w') as f:
                yaml.dump(settings, f, default_flow_style=False, sort_keys=False)
            
            return JSONResponse(content={
                "success": True,
                "message": f"Detector '{detector}' {'enabled' if enabled else 'disabled'}"
            })
        else:
            raise HTTPException(status_code=404, detail=f"Detector '{detector}' not found")
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


# ==========================================
# API ENDPOINTS - MONITORING
# ==========================================
@app.get("/api/monitor/status")
async def get_monitor_status():
    """Get realtime monitoring status"""
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
async def start_realtime_monitoring(interval: int = 30, events_per_check: int = 100):
    """Start realtime monitoring"""
    global realtime_monitor_active, realtime_monitor_thread, multi_monitor
    
    try:
        if realtime_monitor_active and realtime_monitor_thread and realtime_monitor_thread.is_alive():
            return JSONResponse(content={
                "success": False,
                "message": "Realtime monitoring is already running"
            }, status_code=400)
        
        # Initialize monitor
        if multi_monitor is None:
            multi_monitor = MultiTargetMonitor(config)
        
        # Start monitoring in background thread
        import threading
        
        def run_realtime_monitoring():
            global realtime_monitor_active
            try:
                multi_monitor.start_realtime_monitoring(
                    interval_seconds=interval,
                    events_per_check=events_per_check
                )
            except Exception as e:
                print(f"Realtime monitoring error: {e}")
                realtime_monitor_active = False
        
        realtime_monitor_active = True
        realtime_monitor_thread = threading.Thread(target=run_realtime_monitoring, daemon=True)
        realtime_monitor_thread.start()
        
        # Notify WebSocket clients
        for ws in active_websockets:
            try:
                await ws.send_json({
                    "type": "monitoring_started",
                    "message": "Realtime monitoring started"
                })
            except:
                pass
        
        return JSONResponse(content={
            "success": True,
            "message": f"Realtime monitoring started (interval: {interval}s)"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/monitor/stop")
async def stop_realtime_monitoring():
    """Stop realtime monitoring"""
    global realtime_monitor_active, multi_monitor
    
    try:
        if not realtime_monitor_active:
            return JSONResponse(content={
                "success": False,
                "message": "Realtime monitoring is not running"
            }, status_code=400)
        
        # Stop monitoring
        realtime_monitor_active = False
        if multi_monitor:
            multi_monitor.stop_monitoring = True
        
        # Notify WebSocket clients
        for ws in active_websockets:
            try:
                await ws.send_json({
                    "type": "monitoring_stopped",
                    "message": "Realtime monitoring stopped"
                })
            except:
                pass
        
        return JSONResponse(content={
            "success": True,
            "message": "Realtime monitoring stopped"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/monitor/scan")
async def trigger_scan(background_tasks: BackgroundTasks):
    """Trigger a manual security scan"""
    try:
        # Run scan in background
        background_tasks.add_task(run_security_scan)
        
        return JSONResponse(content={
            "success": True,
            "message": "Security scan started"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


async def run_security_scan():
    """Run a security scan"""
    global multi_monitor
    
    try:
        if multi_monitor is None:
            multi_monitor = MultiTargetMonitor(config)
        
        results = multi_monitor.monitor_all_targets(parallel=True)
        
        # Notify WebSocket clients
        for ws in active_websockets:
            try:
                await ws.send_json({
                    "type": "scan_complete",
                    "results": results
                })
            except:
                active_websockets.remove(ws)
    except Exception as e:
        print(f"Error running scan: {e}")


# ==========================================
# API ENDPOINTS - TARGET MANAGEMENT
# ==========================================
@app.get("/api/targets/list")
async def get_targets():
    """Get list of monitoring targets"""
    try:
        import yaml
        
        # Load targets.yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        if not targets_path.exists():
            return JSONResponse(content={
                "success": False,
                "error": "targets.yaml not found"
            }, status_code=404)
        
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)
        
        targets = targets_data.get('targets', [])
        
        return JSONResponse(content={
            "success": True,
            "count": len(targets),
            "targets": targets
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/targets/add")
async def add_target(
    name: str,
    hostname: str,
    username: str,
    password: str,
    enabled: bool = True
):
    """Add a new monitoring target"""
    try:
        import yaml
        
        # Load targets.yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)
        
        if 'targets' not in targets_data:
            targets_data['targets'] = []
        
        # Check if target already exists
        for target in targets_data['targets']:
            if target['name'] == name or target['hostname'] == hostname:
                return JSONResponse(content={
                    "success": False,
                    "error": f"Target with name '{name}' or hostname '{hostname}' already exists"
                }, status_code=400)
        
        # Add new target
        new_target = {
            'name': name,
            'hostname': hostname,
            'username': username,
            'password': password,
            'enabled': enabled
        }
        
        targets_data['targets'].append(new_target)
        
        # Save
        with open(targets_path, 'w') as f:
            yaml.dump(targets_data, f, default_flow_style=False, sort_keys=False)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Target '{name}' added successfully",
            "target": new_target
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.post("/api/targets/update")
async def update_target(
    name: str,
    enabled: Optional[bool] = None,
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None
):
    """Update an existing target"""
    try:
        import yaml
        
        # Load targets.yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)
        
        # Find and update target
        target_found = False
        for target in targets_data.get('targets', []):
            if target['name'] == name:
                target_found = True
                if enabled is not None:
                    target['enabled'] = enabled
                if hostname is not None:
                    target['hostname'] = hostname
                if username is not None:
                    target['username'] = username
                if password is not None:
                    target['password'] = password
                break
        
        if not target_found:
            return JSONResponse(content={
                "success": False,
                "error": f"Target '{name}' not found"
            }, status_code=404)
        
        # Save
        with open(targets_path, 'w') as f:
            yaml.dump(targets_data, f, default_flow_style=False, sort_keys=False)
        
        return JSONResponse(content={
            "success": True,
            "message": f"Target '{name}' updated successfully"
        })
    except Exception as e:
        return JSONResponse(content={
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.delete("/api/targets/delete")
async def delete_target(name: str):
    """Delete a target"""
    try:
        import yaml
        
        # Load targets.yaml
        targets_path = Path(__file__).parent / "config" / "app" / "targets.yaml"
        
        with open(targets_path, 'r') as f:
            targets_data = yaml.safe_load(f)
        
        # Find and remove target
        original_count = len(targets_data.get('targets', []))
        targets_data['targets'] = [t for t in targets_data.get('targets', []) if t['name'] != name]
        
        if len(targets_data['targets']) == original_count:
            return JSONResponse(content={
                "success": False,
                "error": f"Target '{name}' not found"
            }, status_code=404)
        
        # Save
        with open(targets_path, 'w') as f:
            yaml.dump(targets_data, f, default_flow_style=False, sort_keys=False)
        
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
# WEBSOCKET FOR REAL-TIME UPDATES
# ==========================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    active_websockets.append(websocket)
    
    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            
            # Echo back (or handle commands)
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
# FAVICON AND STATIC RESOURCES
# ==========================================
@app.get("/favicon.ico")
async def favicon():
    """Return a simple favicon to avoid 500 errors"""
    # Return 204 No Content - browser won't complain
    from fastapi.responses import Response
    return Response(status_code=204)


# ==========================================
# HEALTH CHECK
# ==========================================
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return JSONResponse(content={
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "mongodb_connected": mongodb is not None
    })


# ==========================================
# STARTUP
# ==========================================
if __name__ == "__main__":
    print("=" * 60)
    print("🌐 Security Monitor Dashboard")
    print("=" * 60)
    print(f"📊 Dashboard URL: http://localhost:8081")
    print(f"📚 API Docs: http://localhost:8081/docs")
    print("=" * 60)
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8081)
