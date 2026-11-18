"""Generate static openapi.json spec from the CentralWatch application."""

import json
from pathlib import Path
import sys

# Add demo-app to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo-app"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "centralwatch-security"))

try:
    from app.main import create_app
    app = create_app()
    openapi_schema = app.openapi()
    
    out_file = Path(__file__).resolve().parent.parent / "openapi.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(openapi_schema, f, indent=2)
    print(f"Successfully generated OpenAPI specification at: {out_file}")
except Exception as e:
    print(f"Error generating OpenAPI schema: {e}")
    sys.exit(1)

