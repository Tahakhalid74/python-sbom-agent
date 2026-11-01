
import requests


def get_fixed_versions(vulnerability_id, package_name):
    """
    Get reported fixed versions from the OSV database.
    These are advisory-specific fixes, not verified
    upgrades for the complete application.
    """

    url = f"https://api.osv.dev/v1/vulns/{vulnerability_id}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        vulnerability = response.json()
        fixed_versions = set()

        for affected in vulnerability.get("affected", []):
            package = affected.get("package", {})

            if package.get("ecosystem") != "PyPI":
                continue

            if package.get("name", "").lower() != package_name.lower():
                continue

            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    if "fixed" in event:
                        fixed_versions.add(event["fixed"])

        return {
            "vulnerability_id": vulnerability_id,
            "package": package_name,
            "reported_fixed_versions": sorted(fixed_versions)
        }

    except (requests.RequestException, ValueError) as error:
        return {
            "vulnerability_id": vulnerability_id,
            "package": package_name,
            "error": str(error)
        }


if __name__ == "__main__":
    result = get_fixed_versions(
        "GHSA-2gwj-7jmv-h26r",
        "django"
    )

    print("\nRemediation Results")
    print("----------------------------")
    print("Vulnerability:", result["vulnerability_id"])
    print("Package:", result["package"])

    if "error" in result:
        print("Error:", result["error"])
    else:
        print(
            "Reported Fixed Versions:",
            result["reported_fixed_versions"]
        )
