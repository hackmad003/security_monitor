# src/__init__.py

"""
Windows Security Event Monitor
Main package exports
"""

from .core.monitor import SecurityMonitor
from .core.event_reader import EventReader
from .utils.config import Config

__version__ = "2.0.0"
__author__ = "hackmad"

__all__ = [
    "SecurityMonitor",
    "EventReader", 
    "Config"
]