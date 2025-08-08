"""
Custom exceptions for PyAZSentinel operations.
"""


class AzureSentinelError(Exception):
    """Base exception for Azure Sentinel operations."""
    pass


class AuthenticationError(AzureSentinelError):
    """Authentication related errors."""
    pass


class ResourceNotFoundError(AzureSentinelError):
    """Resource not found errors."""
    pass


class ValidationError(AzureSentinelError):
    """Data validation errors."""
    pass


class ConfigurationError(AzureSentinelError):
    """Configuration related errors."""
    pass


class APIError(AzureSentinelError):
    """Azure API related errors."""
    pass
