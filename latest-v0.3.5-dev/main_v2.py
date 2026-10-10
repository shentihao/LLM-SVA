import argparse
import json
from pathlib import Path

from analysis.scanner_v2 import scan_project_v2
from llm.analyzer import LLMAnalyzer
from verification.confidence import calculate_confidence


def main():
    parser = argparse.ArgumentParser(description="LLM-SVA v0.2")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="data/results-v2")
    parser.add_argument("--cwe", default=None)
    parser.add_argument("--llm", action="store_true")
    args = parser.parse_args()

    findings = scan_project_v2(Path(args.input), cwe=args.cwe)
    analyzer = LLMAnalyzer() if args.llm else None

    results = []
    for item in findings:
        if analyzer:
            llm_result = analyzer.analyze(item)
        else:
            llm_result = {
                "is_vulnerable": item["verification"]["path_valid"],
                "confidence": 0.50,
                "reason": "V0.2 local AST-backed taint analysis only.",
                "repair": item["rule"].get("repair", "")
            }

        item["llm"] = llm_result
        item["final"] = calculate_confidence(item, llm_result)
        item.pop("rule", None)
        results.append(item)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    print(f"Candidates: {len(results)}")
    print(f"Result: {out / 'findings.json'}")


if __name__ == "__main__":
    main()
