"""
DevPulse - Test Configuration
Shared fixtures and setup for all tests
"""

import pytest
import sys
import os

# Add src to path for all tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Set test environment variables
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_devpulse.db")
os.environ.setdefault("USE_DATABASE", "false")  # Use in-memory for fast tests
os.environ.setdefault("JWT_SECRET", "test-secret-key")
os.environ.setdefault("ENVIRONMENT", "test")
