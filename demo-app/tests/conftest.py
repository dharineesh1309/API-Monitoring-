"""Test path setup for the demo-app package."""

import sys
from pathlib import Path

DEMO_APP_ROOT = Path(__file__).resolve().parents[1]
if str(DEMO_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(DEMO_APP_ROOT))
