"""
conftest.py — pytest root configuration.

This file lives at the project root and tells pytest to add the project
directory to sys.path, so 'import app' and 'from core.X import Y' resolve
correctly from any test file inside tests/.
"""
import sys
import os

# Ensure the project root is always on the path
sys.path.insert(0, os.path.dirname(__file__))
