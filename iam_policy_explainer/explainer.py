import argparse
import json
import sys


def parse_args():
    """Parse command-line arguments and return them."""
    parser = argparse.ArgumentParser(
        description="Read an IAM policy JSON file and print a human-readable summary."
    )
    parser.add_argument(
        "policy_file",
        type=str,
        help="Path to the IAM policy JSON file to analyze.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print normalized actions and resources for each statement.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report instead of human-readable text.",
    )
    return parser.parse_args()


def load_policy(path):
    """Load a JSON policy from disk and return it as a dict."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found -> {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}", file=sys.stderr)
        print(f"       {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied reading {path}", file=sys.stderr)
        sys.exit(1)


def normalize_to_list(value):
    """IAM allows string OR list for Action/Resource. Return always a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def get_statements(policy):
    """IAM 'Statement' may be a single dict or a list. Return always a list."""
    stmt = policy.get("Statement")
    if stmt is None:
        return []
    if isinstance(stmt, dict):
        return [stmt]
    if isinstance(stmt, list):
        return stmt
    return []


def analyze_statement(statement):
    """Return a dict of normalized fields plus risk flags."""
    effect = statement.get("Effect", "Unknown")
    actions = normalize_to_list(statement.get("Action"))
    not_actions = normalize_to_list(statement.get("NotAction"))
    resources = normalize_to_list(statement.get("Resource"))
    not_resources = normalize_to_list(statement.get("NotResource"))
    principal = statement.get("Principal")
    has_condition = "Condition" in statement

    has_star_action = "*" in actions
    has_service_wildcard = any(
        isinstance(a, str) and a.endswith(":*") for a in actions
    )
    has_star_resource = "*" in resources
    has_public_principal = "*" in normalize_to_list(principal)
    has_wildcard = (
        has_star_action
        or has_service_wildcard
        or has_star_resource
        or bool(not_actions)
        or bool(not_resources)
    )

    risk_reasons = []

    if effect == "Allow":
        if has_star_action:
            risk_reasons.append("Action is '*' (all actions on all services)")
        if has_service_wildcard:
            risk_reasons.append("Wildcard service action like 's3:*'")
        if not_actions:
            risk_reasons.append("Uses NotAction with Allow (brittle deny-list style)")
        if has_star_resource:
            risk_reasons.append("Resource is '*' (all resources)")
        if not_resources:
            risk_reasons.append("Uses NotResource with Allow")
        if not has_condition and has_wildcard:
            risk_reasons.append("No Condition block to constrain the wildcard")
        if has_public_principal:
            risk_reasons.append("Principal is '*' — potentially public")

    is_overly_permissive = (
        effect == "Allow"
        and (
            has_star_action
            or has_service_wildcard
            or has_star_resource
            or bool(not_actions)
            or bool(not_resources)
        )
    )

    return {
        "effect": effect,
        "actions": actions,
        "not_actions": not_actions,
        "resources": resources,
        "not_resources": not_resources,
        "principal": principal,
        "has_condition": has_condition,
        "risk_reasons": risk_reasons,
        "is_overly_permissive": is_overly_permissive,
    }


def score_statement(analysis):
    """Return a severity label for a single statement analysis."""
    if analysis["effect"] != "Allow":
        return "INFO"

    actions = analysis["actions"]
    resources = analysis["resources"]
    not_actions = analysis["not_actions"]
    not_resources = analysis["not_resources"]
    has_condition = analysis["has_condition"]
    principal_list = normalize_to_list(analysis["principal"])

    has_star_action = "*" in actions
    has_star_resource = "*" in resources
    has_service_wildcard = any(
        isinstance(a, str) and a.endswith(":*") for a in actions
    )
    has_public_principal = "*" in principal_list

    if has_star_action and has_star_resource and not has_condition:
        return "CRITICAL"

    if has_star_action or not_actions or has_public_principal:
        return "HIGH"

    if has_service_wildcard or has_star_resource or not_resources:
        return "MEDIUM"

    return "LOW"


SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def highest_severity(severities):
    """Return the worst severity from a list of labels."""
    if not severities:
        return "INFO"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


def format_statement_summary(statement, index, analysis, severity):
    """Return a human-readable multi-line string for one statement."""
    sid = statement.get("Sid")
    header = f"Statement {index}"
    if sid:
        header += f" (Sid: {sid})"

    lines = [header]
    lines.append(f"  Effect: {analysis['effect']}")
    lines.append(f"  Severity: {severity}")

    if analysis["actions"]:
        lines.append(f"  Actions: {', '.join(map(str, analysis['actions']))}")
    if analysis["not_actions"]:
        lines.append(f"  NotAction: {', '.join(map(str, analysis['not_actions']))}")
    if analysis["resources"]:
        lines.append(f"  Resources: {', '.join(map(str, analysis['resources']))}")
    if analysis["not_resources"]:
        lines.append(
            f"  NotResource: {', '.join(map(str, analysis['not_resources']))}"
        )

    lines.append(f"  Condition: {'yes' if analysis['has_condition'] else 'no'}")

    if analysis["principal"] is not None:
        lines.append(f"  Principal: {analysis['principal']}")

    if analysis["is_overly_permissive"]:
        lines.append("  Assessment: OVERLY PERMISSIVE")
        for r in analysis["risk_reasons"]:
            lines.append(f"    - {r}")
    elif analysis["risk_reasons"]:
        lines.append("  Assessment: REVIEW RECOMMENDED")
        for r in analysis["risk_reasons"]:
            lines.append(f"    - {r}")
    else:
        lines.append("  Assessment: looks scoped")

    return "\n".join(lines)


def print_overall_summary(analyses, severities):
    """Print the final tally across all statements."""
    total = len(analyses)
    allow_count = sum(1 for a in analyses if a["effect"] == "Allow")
    deny_count = sum(1 for a in analyses if a["effect"] == "Deny")
    risky = [i + 1 for i, a in enumerate(analyses) if a["is_overly_permissive"]]
    worst = highest_severity(severities)

    print("=" * 55)
    print("OVERALL SUMMARY")
    print("=" * 55)
    print(f"Total statements   : {total}")
    print(f"Allow statements   : {allow_count}")
    print(f"Deny statements    : {deny_count}")
    print(f"Overly permissive  : {len(risky)}")
    if risky:
        print(f"Risky statement #s : {', '.join(map(str, risky))}")
    print(f"Highest severity   : {worst}")


def build_report(policy, policy_path, statements, analyses, severities):
    """Build a machine-readable report dict for --json output."""
    return {
        "file": policy_path,
        "version": policy.get("Version", "unknown"),
        "summary": {
            "total_statements": len(statements),
            "allow": sum(1 for a in analyses if a["effect"] == "Allow"),
            "deny": sum(1 for a in analyses if a["effect"] == "Deny"),
            "overly_permissive": sum(
                1 for a in analyses if a["is_overly_permissive"]
            ),
            "highest_severity": highest_severity(severities),
        },
        "statements": [
            {
                "index": i + 1,
                "sid": stmt.get("Sid"),
                "effect": analysis["effect"],
                "severity": severities[i],
                "actions": analysis["actions"],
                "not_actions": analysis["not_actions"],
                "resources": analysis["resources"],
                "not_resources": analysis["not_resources"],
                "principal": analysis["principal"],
                "has_condition": analysis["has_condition"],
                "is_overly_permissive": analysis["is_overly_permissive"],
                "risk_reasons": analysis["risk_reasons"],
            }
            for i, (stmt, analysis) in enumerate(zip(statements, analyses))
        ],
    }


def main():
    args = parse_args()
    policy = load_policy(args.policy_file)
    statements = get_statements(policy)

    analyses = [analyze_statement(s) for s in statements]
    severities = [score_statement(a) for a in analyses]

    if args.json:
        report = build_report(
            policy, args.policy_file, statements, analyses, severities
        )
        print(json.dumps(report, indent=2))
        if any(s in ("HIGH", "CRITICAL") for s in severities):
            sys.exit(1)
        return

    print(f"Policy Version : {policy.get('Version', 'unknown')}")
    print(f"Statements     : {len(statements)}")
    print()

    for i, stmt in enumerate(statements, start=1):
        print(format_statement_summary(stmt, i, analyses[i - 1], severities[i - 1]))
        if args.verbose:
            print(f"  [verbose] actions normalized: {analyses[i - 1]['actions']}")
            print(f"  [verbose] resources normalized: {analyses[i - 1]['resources']}")
        print()

    print_overall_summary(analyses, severities)

    if any(s in ("HIGH", "CRITICAL") for s in severities):
        sys.exit(1)


if __name__ == "__main__":
    main()