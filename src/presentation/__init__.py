"""Presentation layer for Identity module.

This layer provides the external interfaces for the Identity module including
REST API endpoints, GraphQL schema, and middleware for authentication.
"""

from .app import create_app, run_app
from .config import PresentationConfig, get_presentation_config

__all__ = [
    "create_app",
    "run_app",
    "PresentationConfig",
    "get_presentation_config",
]
