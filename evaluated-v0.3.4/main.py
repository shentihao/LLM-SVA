import argparse
import json
from pathlib import Path

from analysis.scanner import scan_project
from llm.analyzer import LLMAnalyzer
from verification.confidence import calculate_confidence


def main():
    parser = argparse.ArgumentParser(description="LLM-SVA Java vulnerability auditor")
    parser.add_argument("--input", required=True, help="Java source directory")
    parser.add_argument("--output", default="data/results")
    parser.add_argument("--cwe", default=None)
    parser.add_argument("--llm", action="store_true")
    args = parser.parse_args()

    findings = scan_project(Path(args.input), cwe=args.cwe)

    analyzer = LLMAnalyzer() if args.llm else None
    final_findings = []

    for item in findings:
        llm_result = analyzer.analyze(item) if analyzer else {
            "is_vulnerable": item["verification"]["path_valid"],
            "confidence": 0.50,
            "reason": "Local static candidate/path analysis only.",
            "repair": item["rule"].get("repair", "")
        }

        item["llm"] = llm_result
        item["final"] = calculate_confidence(item, llm_result)
        item.pop("rule", None)
        final_findings.append(item)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(
        json.dumps(final_findings, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    import csv
    with (out / "findings.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "file", "method", "cwe", "type", "source", "sink",
                "path_valid", "sanitization", "llm_confidence",
                "final_confidence", "status"
            ]
        )
        writer.writeheader()
        for x in final_findings:
            writer.writerow({
                "file": x["file"],
                "method": x["method"],
                "cwe": x["vulnerability"]["cwe"],
                "type": x["vulnerability"]["type"],
                "source": x["source"]["function"],
                "sink": x["sink"]["function"],
                "path_valid": x["verification"]["path_valid"],
                "sanitization": x["verification"]["sanitization_absent"] is False,
                "llm_confidence": x["llm"]["confidence"],
                "final_confidence": x["final"]["confidence"],
                "status": x["final"]["status"]
            })

    print(f"Scanned candidates: {len(final_findings)}")
    print(f"JSON: {out / 'findings.json'}")
    print(f"CSV : {out / 'findings.csv'}")


if __name__ == "__main__":
    main()
