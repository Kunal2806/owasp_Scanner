import subprocess, json
from fastapi import FastAPI, UploadFile, File
from typing import Dict, Any, List

app = FastAPI()

def format_bandit_report(raw_json: Dict[str, Any]) -> Dict[str, Any]:
    results = raw_json.get("results", [])
    metrics = raw_json.get("metrics", {}).get("_totals", {})

    # Summary
    summary = {
        "high": metrics.get("SEVERITY.HIGH", 0),
        "medium": metrics.get("SEVERITY.MEDIUM", 0),
        "low": metrics.get("SEVERITY.LOW", 0),
        "total": metrics.get("SEVERITY.HIGH", 0) 
                 + metrics.get("SEVERITY.MEDIUM", 0) 
                 + metrics.get("SEVERITY.LOW", 0),
        "loc": metrics.get("loc", 0),
    }

    # Issues
    issues: List[Dict[str, Any]] = []
    for issue in results:
        issues.append({
            "file": issue.get("filename"),
            "line": issue.get("line_number"),
            "severity": issue.get("issue_severity"),
            "confidence": issue.get("issue_confidence"),
            "cwe": issue.get("issue_cwe", {}).get("id"),
            "description": issue.get("issue_text"),
            "code": issue.get("code"),
            "recommendation_link": issue.get("more_info"),
            "test_id": issue.get("test_id"),
            "test_name": issue.get("test_name"),
        })

    return {
        "summary": summary,
        "issues": issues
    }

@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
    # Save uploaded file
    contents = await file.read()
    with open(file.filename, "wb") as f:
        f.write(contents)

    # Run Bandit scan
    result = subprocess.run(
        ["bandit", "-f", "json", "-r", file.filename],
        capture_output=True, text=True
    )

    findings = json.loads(result.stdout)

    # Use the formatter before returning
    report = format_bandit_report(findings)
    return report
