"""
Entry point for running Monster as a module.

Usage:
    python -m monster --target example.com
    python -m monster --target example.com --dry-run
"""

from monster.main import main

if __name__ == "__main__":
    main()
