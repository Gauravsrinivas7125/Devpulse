"""Setup for standalone Thinking Tokens Library"""

from setuptools import setup, find_packages

setup(
    name="devpulse-thinking-tokens",
    version="1.0.0",
    description="LLM Thinking Token Attribution & Cost Tracking Library",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="DevPulse",
    author_email="support@devpulse.io",
    url="https://github.com/anugownori/pulse-dashboard",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],  # No external dependencies
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries",
    ],
)
