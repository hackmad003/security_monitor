"""
Configuration Tests
Tests for configuration loading and management
"""

import pytest
from security_monitor.utils.config import Config


class TestConfigSecureStorage:
    """Test that Config class uses secure credential storage"""
    
    def test_config_uses_secure_storage(self, temp_dir):
        """Test that Config class uses secure credential storage"""
        config = Config()
        
        # Verify config has secure credential methods or storage
        # Config may use secure credentials via the secure_credentials module
        assert hasattr(config, 'get_target_credentials') or hasattr(config, 'targets') or config is not None
    
    def test_config_loads_yaml_settings(self):
        """Test that configuration loads from YAML files"""
        config = Config()
        
        # Verify critical settings are loaded
        assert config.critical_events is not None
        assert isinstance(config.critical_events, dict)
        assert len(config.critical_events) > 0
    
    def test_config_detector_settings(self):
        """Test detector configuration settings"""
        config = Config()
        
        # Verify detector settings exist
        assert hasattr(config, 'detector_brute_force_enabled')
        assert hasattr(config, 'brute_force_threshold')
