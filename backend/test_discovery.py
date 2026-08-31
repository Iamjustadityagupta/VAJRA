from pathlib import Path

from discovery import DiscoveryManager, PythonRulesEngine


def test_detect_languages_finds_supported_and_unsupported_sources(tmp_path: Path):
    (tmp_path / "app.py").write_text("print(1)\n")
    (tmp_path / "widget.js").write_text("console.log(1);\n")

    manager = DiscoveryManager()

    assert manager.detect_languages(tmp_path) == ["python", "javascript"]
    assert manager.supported_languages(tmp_path) == ["python"]


def test_python_rules_normalize_finding_contract(tmp_path: Path):
    source = """from flask import request

def lookup(db):
    name = request.args.get("name", "")
    query = "SELECT id, name FROM users WHERE name = '" + name + "'"
    return db.execute(query).fetchall()
""".strip()
    (tmp_path / "app.py").write_text(source)

    findings = PythonRulesEngine().scan(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["language"] == "python"
    assert finding["type"] == "python.sql-injection"
    assert finding["path"] == "app.py"
    assert finding["severity"] == "ERROR"
    assert finding["start"]["line"] == 5
