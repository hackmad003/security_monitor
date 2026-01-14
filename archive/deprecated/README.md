# Deprecated Files

This directory contains files that have been superseded by newer implementations.

## Files and Their Status

### ✅ `setup.py` - **NOT Deprecated, Should Be Restored**

**Status**: This file is NOT actually deprecated and should be moved back to the project root.

**Why it's needed**:
- Required for proper Python package installation
- Enables `pip install -e .` for development
- Defines entry points for CLI commands
- Specifies package metadata and dependencies

**Recommendation**: Move to root directory and update paths if needed.

---

### ❌ `web_dashboard.py` - **Truly Deprecated**

**Status**: Replaced by `security_monitor/dashboard/web_dashboard_secure.py`

**Why it's deprecated**:
- Missing JWT authentication (security vulnerability)
- No rate limiting
- No input validation with Pydantic models
- Uses old import structure (`from security_monitor.database`)
- No secure WebSocket authentication

**Current replacement**: `security_monitor/dashboard/web_dashboard_secure.py`

**Key improvements in new version**:
- ✅ JWT authentication required for sensitive endpoints
- ✅ Rate limiting middleware
- ✅ Pydantic models for input validation
- ✅ Secure WebSocket with token validation
- ✅ Updated imports to use `storage` instead of `database`
- ✅ Better error handling and security

**Recommendation**: Keep as archived reference, do not use.

---

### ❌ `run_dashboard.py` - **Truly Deprecated**

**Status**: Replaced by `scripts/start_dashboard_simple.py`

**Why it's deprecated**:
- Uses old import structure (`from security_monitor.database`)
- Located in wrong directory (archive instead of scripts)
- Functionality merged into `scripts/start_dashboard_simple.py`

**Current replacement**: `scripts/start_dashboard_simple.py`

**Recommendation**: Keep as archived reference, do not use.

---

## Summary

| File | Status | Action Needed |
|------|--------|---------------|
| `setup.py` | ⚠️ **NOT DEPRECATED** | Move to root directory |
| `web_dashboard.py` | ✅ Truly deprecated | Keep archived |
| `run_dashboard.py` | ✅ Truly deprecated | Keep archived |

## Migration Guide

### If you need setup.py functionality:

```bash
# Move setup.py back to root
mv archive/deprecated/setup.py ./setup.py

# Install in development mode
pip install -e .

# This will enable commands like:
security-monitor --mode single
security-dashboard
```

### If you're using the old dashboard files:

**DO NOT USE THESE FILES**. They have security vulnerabilities. Use the new secure versions:

- Old: `archive/deprecated/web_dashboard.py`
- New: `security_monitor/dashboard/web_dashboard_secure.py`

Run the new dashboard with:
```bash
python scripts/START_HERE.bat
# or
python -m security_monitor.dashboard.web_dashboard_secure
```

## Why These Files Were Deprecated

1. **Security Improvements**: New versions include authentication, rate limiting, and input validation
2. **Code Organization**: Better module structure with `security_monitor.storage` instead of `security_monitor.database`
3. **Best Practices**: Pydantic models for type safety and validation
4. **Maintainability**: Cleaner code structure and better separation of concerns
