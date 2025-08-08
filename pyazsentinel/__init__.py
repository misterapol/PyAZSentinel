"""
PyAZSentinel - Python SDK for Azure Sentinel

A comprehensive Python library for managing Azure Sentinel resources.
"""

__version__ = "0.1.0"
__author__ = "misterapol"

from .client import AzureSentinelClient
from .auth.authentication import AzureSentinelAuth

__all__ = ["AzureSentinelClient", "AzureSentinelAuth"]
