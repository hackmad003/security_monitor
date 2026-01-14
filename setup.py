"""
Setup script for Windows Security Event Monitor
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = requirements_file.read_text(encoding="utf-8").strip().split("\n")

setup(
    name="security-monitor",
    version="1.0.0",
    author="Security Team",
    author_email="security@company.com",
    description="Windows Security Event Monitor with real-time threat detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/security-monitor",
    packages=find_packages(include=["security_monitor", "security_monitor.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "security-monitor=main:main",
            "security-dashboard=web_dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "security_monitor": [
            "config/app/*.yaml",
            "config/splunk/dashboards/*.xml",
            "web/*.html",
        ],
    },
)
