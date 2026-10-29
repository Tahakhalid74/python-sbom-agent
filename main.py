
import requests
import json

# Read sample dependencies
with open("requirments.txt", "r") as file:
    dependencies = file.readlines()

# Scan each package
# Store results for all scanned dependencies
scan_results = []

for dependency in dependencies:
    dependency = dependency.strip()

    if "==" not in dependency:
        continue

    package_name, version = dependency.split("==", 1)

    print(f"\nScanning {package_name} version {version}")

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=15
        )

        response.raise_for_status()
        vulnerabilities = response.json().get("vulns", [])

        # Group vulnerabilities by CVE
        unique_vulnerabilities = {}

        for vuln in vulnerabilities:
            aliases = vuln.get("aliases", [])
            cves = sorted(
                alias for alias in aliases
                if alias.startswith("CVE-")
            )

            key = tuple(cves) if cves else vuln["id"]

            if key not in unique_vulnerabilities:
                unique_vulnerabilities[key] = {
                    "cve": ", ".join(cves) or "Not available",
                    "description": "Not available",
                    "severity": "Not available"
                }

            record = unique_vulnerabilities[key]

            if vuln.get("summary"):
                record["description"] = vuln["summary"]

            severity = vuln.get(
                "database_specific", {}
            ).get("severity")

            if severity:
                record["severity"] = severity

        print(f"OSV records: {len(vulnerabilities)}")
        print(
            f"Unique vulnerability groups: "
            f"{len(unique_vulnerabilities)}"
        )

        # Step 6: Calculate preliminary risk scores
        severity_scores = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MODERATE": 4,
            "MEDIUM": 4,
            "LOW": 1
        }

        risk_scores = []

        for record in unique_vulnerabilities.values():
            severity = record["severity"].upper()

            score = severity_scores.get(severity)

            if score is not None:
                risk_scores.append(score)

        # Highest severity determines the initial package score
        if risk_scores:
            package_score = max(risk_scores)
        else:
            package_score = None

        print("\n========== PACKAGE RISK SUMMARY ==========")
        print(f"Package: {package_name}")
        print(f"Version: {version}")
        print(f"Unique vulnerability groups: {len(unique_vulnerabilities)}")

        if package_score is None:
            print("Risk score: Not rated")
        else:
            print(f"Preliminary risk score: {package_score}/10")

        print("==========================================")

        # Step 7: Save structured package results
        package_result = {
            "package": package_name,
            "version": version,
            "osv_records": len(vulnerabilities),
            "unique_vulnerability_count": len(unique_vulnerabilities),
            "risk_score": package_score,
            "vulnerabilities": []
        }

        for record in unique_vulnerabilities.values():
            package_result["vulnerabilities"].append({
                "cve": record["cve"],
                "description": record["description"],
                "severity": record["severity"]
            })

        scan_results.append(package_result)

        for record in unique_vulnerabilities.values():
            print(f"\nCVE: {record['cve']}")
            print(f"Description: {record['description']}")
            print(f"Severity: {record['severity']}")
            print("-" * 40)

    except requests.RequestException as error:
        print(f"API request failed: {error}")


# Step 8: Export all scan results to JSON
with open("scan_results.json", "w") as file:
    json.dump(scan_results, file, indent=4)

print("\nScan results saved to scan_results.json")

