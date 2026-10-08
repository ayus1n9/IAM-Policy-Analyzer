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

    risk_reasons = []

    if effect == "Allow":
        if "*" in actions:
            risk_reasons.append("Action is '*' (all actions on all services)")
        if any(isinstance(a, str) and a.endswith(":*") for a in actions):
            risk_reasons.append("Wildcard service action like 's3:*'")
        if not_actions:
            risk_reasons.append("Uses NotAction with Allow (brittle deny-list style)")
        if "*" in resources:
            risk_reasons.append("Resource is '*' (all resources)")
        if not_resources:
            risk_reasons.append("Uses NotResource with Allow")
        if not has_condition:
            risk_reasons.append("No Condition block (no extra guardrails)")
        if "*" in normalize_to_list(principal):
            risk_reasons.append("Principal is '*' — potentially public")

    is_overly_permissive = (
        effect == "Allow"
        and (
            "*" in actions
            or any(isinstance(a, str) and a.endswith(":*") for a in actions)
            or "*" in resources
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


def format_statement_summary(statement, index, analysis):
    """Return a human-readable multi-line string for one statement."""
    sid = statement.get("Sid")
    header = f"Statement {index}"
    if sid:
        header += f" (Sid: {sid})"

    lines = [header]
    lines.append(f"  Effect: {analysis['effect']}")

    if analysis["actions"]:
        lines.append(f"  Actions: {', '.join(map(str, analysis['actions']))}")
    if analysis["not_actions"]:
        lines.append(f"  NotAction: {', '.join(map(str, analysis['not_actions']))}")
    if analysis["resources"]:
        lines.append(f"  Resources: {', '.join(map(str, analysis['resources']))}")
    if analysis["not_resources"]:
        lines.append(f"  NotResource: {', '.join(map(str, analysis['not_resources']))}")

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


def print_overall_summary(analyses):
    """Print the final tally across all statements."""
    total = len(analyses)
    allow_count = sum(1 for a in analyses if a["effect"] == "Allow")
    deny_count = sum(1 for a in analyses if a["effect"] == "Deny")
    risky = [i + 1 for i, a in enumerate(analyses) if a["is_overly_permissive"]]

    print("=" * 55)
    print("OVERALL SUMMARY")
    print("=" * 55)
    print(f"Total statements  : {total}")
    print(f"Allow statements  : {allow_count}")
    print(f"Deny statements   : {deny_count}")
    print(f"Overly permissive : {len(risky)}")
    if risky:
        print(f"Risky statements  : {', '.join(map(str, risky))}")


def main():
    args = parse_args()
    policy = load_policy(args.policy_file)
    statements = get_statements(policy)

    print(f"Policy Version : {policy.get('Version', 'unknown')}")
    print(f"Statements     : {len(statements)}")
    print()

    analyses = []
    for i, stmt in enumerate(statements, start=1):
        analysis = analyze_statement(stmt)
        analyses.append(analysis)
        print(format_statement_summary(stmt, i, analysis))

        if args.verbose:
            print(f"  [verbose] actions normalized: {analysis['actions']}")
            print(f"  [verbose] resources normalized: {analysis['resources']}")
        print()

    print_overall_summary(analyses)


if __name__ == "__main__":
    main()