"""Allow running as: python -m monster"""
import sys

try:
    from monster.main import main
except ImportError:
    def main():
        print("Monster main module not yet installed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
