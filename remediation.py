
import requests


def extract_fixed_versions(vulnerability, package_name):
    """
    Extract reported fixed versions from an OSV vulnerability record.
    """

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

    return sorted(fixed_versions)


def get_fixed_versions(vulnerability_id, package_name):
    """
    Retrieve vulnerability details from OSV and extract fixes.
    """

    url = f"https://api.osv.dev/v1/vulns/{vulnerability_id}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        vulnerability = response.json()

        return {
            "vulnerability_id": vulnerability_id,
            "package": package_name,
            "reported_fixed_versions": extract_fixed_versions(
                vulnerability, package_name
            )
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
    print(result)
