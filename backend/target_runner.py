from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path


def load(path: Path):
    name = f"vajra_target_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError("Unable to load target module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return name, module


def main() -> int:
    if len(sys.argv) != 4:
        print(json.dumps({"ok": False, "error": "usage: target_runner.py <path> <metadata-json> <payload>"}))
        return 2
    path = Path(sys.argv[1]).resolve()
    metadata = json.loads(sys.argv[2])
    payload = sys.argv[3]
    name, module = load(path)
    try:
        if not hasattr(module, "app"):
            raise RuntimeError("Target does not expose Flask app named 'app'")
        route = metadata.get("endpoint")
        if not route:
            raise RuntimeError("No Flask endpoint metadata available")
        parameter = metadata.get("parameter") or "input"
        method = str(metadata.get("method") or "GET").upper()
        data = {parameter: payload}
        with module.app.test_client() as client:
            if method == "POST": response = client.post(route, data=data)
            elif method == "PUT": response = client.put(route, data=data)
            elif method == "PATCH": response = client.patch(route, data=data)
            elif method == "DELETE": response = client.delete(route, query_string=data)
            else: response = client.get(route, query_string=data)
        print(json.dumps({"ok": True, "status_code": response.status_code, "body": response.get_data(as_text=True)}))
        return 0
    finally:
        sys.modules.pop(name, None)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        raise SystemExit(1)
