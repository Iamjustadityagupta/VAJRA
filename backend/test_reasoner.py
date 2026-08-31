from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from analyzer import scan_python
from llm_reasoner import LLMReasoner


def test_demo_reasoner_patches_both_findings():
    root = Path(__file__).resolve().parents[1] / "target_app"
    findings = scan_python(root)
    reasoner = LLMReasoner()
    assert {f["extra"]["metadata"]["kind"] for f in findings} == {"sql-injection", "command-injection"}
    for finding in findings:
        source = (root / finding["path"]).read_text(encoding="utf-8")
        result = reasoner.reason_and_patch(finding, source, {"exploitable": True, "payload": "synthetic"})
        assert result["patched_code"] != source
        assert result["finding_kind"] == finding["extra"]["metadata"]["kind"]
