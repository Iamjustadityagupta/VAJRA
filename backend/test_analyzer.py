import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyzer import scan_python


class AnalyzerTests(unittest.TestCase):
    def scan(self, source: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(source, encoding="utf-8")
            return scan_python(root)

    def test_sql_injection_detected_without_seed_formatting(self):
        source = '''from flask import Flask, request\nimport sqlite3\napp = Flask(__name__)\n@app.get("/lookup")\ndef lookup():\n    value = request.args.get("q")\n    statement = "SELECT * FROM users WHERE name = '" + value + "'"\n    return str(sqlite3.connect(":memory:").execute(statement).fetchall())\n'''
        findings = self.scan(source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["extra"]["metadata"]["kind"], "sql-injection")
        self.assertEqual(findings[0]["extra"]["metadata"]["endpoint"], "/lookup")
        self.assertEqual(findings[0]["extra"]["metadata"]["parameter"], "q")

    def test_command_injection_detected_with_os_system(self):
        source = '''from flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route("/run")\ndef run():\n    value = request.form.get("cmd")\n    command = "echo " + value\n    os.system(command)\n    return "ok"\n'''
        findings = self.scan(source)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["extra"]["metadata"]["kind"], "command-injection")
        self.assertEqual(findings[0]["extra"]["metadata"]["endpoint"], "/run")
        self.assertEqual(findings[0]["extra"]["metadata"]["parameter"], "cmd")


if __name__ == "__main__":
    unittest.main()
