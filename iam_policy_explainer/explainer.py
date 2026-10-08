import argparse
import json
import sys


PRIVESC_ACTIONS = {
    "iam:createpolicyversion": (
        "Create a new version of a customer-managed IAM policy; "
        "if made default, it can change the policy's effective permissions"
    ),
    "iam:setdefaultpolicyversion": (
        "Change the default version of a customer-managed IAM policy, "
        "potentially changing its effective permissions"
    ),
    "iam:createaccesskey": "Create access keys for any user (persistence)",
    "iam:createloginprofile": "Create a console password for a user",
    "iam:updateloginprofile": "Reset another user's console password",
    "iam:attachuserpolicy": "Attach a managed policy to any user",
    "iam:attachgrouppolicy": "Attach a managed policy to any group",
    "iam:attachrolepolicy": "Attach a managed policy to any role",
    "iam:putuserpolicy": "Add an inline policy to any user",
    "iam:putgrouppolicy": "Add an inline policy to any group",
    "iam:putrolepolicy": "Add an inline policy to any role",
    "iam:addusertogroup": "Add a user to a group and inherit its permissions",
    "iam:updateassumerolepolicy": "Change who can assume a role",
    "iam:passrole": (
        "Pass an IAM role to an AWS service; combined with a suitable "
        "compute/service action, this may enable privilege escalation"
    ),
    "sts:assumerole": (
        "Assume an IAM role; privilege-escalation impact depends on "
        "the permissions and trust policy of the target role"
    ),
    "lambda:createfunction": "Create a Lambda that runs as a chosen role",
    "lambda:invokefunction": "Invoke a Lambda — may run with elevated perms",
    "lambda:updatefunctioncode": "Replace a Lambda's code — runs as its execution role",
    "ec2:runinstances": (
        "Launch EC2 instances; when combined with iam:PassRole, "
        "this may enable privilege escalation depending on the passed role"
    ),
    "glue:createdevendpoint": "Create a Glue dev endpoint — remote code execution with role creds",
    "cloudformation:createstack": "Deploy a CFN stack that runs with a chosen role",
    "datapipeline:createpipeline": "Create a Data Pipeline that runs as a role",
    "datapipeline:putpipelinedefinition": "Replace a Data Pipeline definition — runs as its role",
    "codestar:createproject": "Create a CodeStar project — RCE with role's credentials",
    "ssm:sendcommand": "Run shell commands on EC2 instances via SSM",
}

COMPUTE_ACTIONS = {
    "ec2:runinstances",
    "lambda:createfunction",
    "lambda:updatefunctioncode",
    "lambda:invokefunction",
    "glue:createdevendpoint",
    "cloudformation:createstack",
    "datapipeline:createpipeline",
    "datapipeline:putpipelinedefinition",
    "codestar:createproject",
}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


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
            policy = json.load(f)

        if not isinstance(policy, dict):
            print(
                "Error: IAM policy must be a JSON object at the top level",
                file=sys.stderr,
            )
            sys.exit(1)

        return policy
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

def principal_contains_wildcard(principal):
    """Return True when an IAM Principal contains a wildcard value."""
    if principal == "*":
        return True

    if isinstance(principal, list):
        return any(principal_contains_wildcard(item) for item in principal)

    if isinstance(principal, dict):
        return any(
            principal_contains_wildcard(value)
            for value in principal.values()
        )

    return False


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


def detect_privesc(analysis):
    """Return list of {action, reason} for privesc actions in this statement."""
    if analysis["effect"] != "Allow":
        return []

    actions = analysis["actions"]
    actions_lower = [a.lower() for a in actions if isinstance(a, str)]

    if "*" in actions_lower:
        return [{
            "action": "*",
            "reason": f"Wildcard covers all {len(PRIVESC_ACTIONS)} known privilege-escalation actions",
        }]

    findings = []
    seen_service_wildcards = set()

    for action in actions:
        if not isinstance(action, str):
            continue
        key = action.lower()

        if key in PRIVESC_ACTIONS:
            findings.append({"action": action, "reason": PRIVESC_ACTIONS[key]})
        elif key.endswith(":*"):
            service_prefix = key.split(":")[0] + ":"
            if service_prefix in seen_service_wildcards:
                continue
            covered = [a for a in PRIVESC_ACTIONS if a.startswith(service_prefix)]
            if covered:
                seen_service_wildcards.add(service_prefix)
                findings.append({
                    "action": action,
                    "reason": f"Service wildcard covers {len(covered)} known privilege-escalation action(s)",
                })

    return findings


def has_passrole_and_compute(actions):
    """True if PassRole appears alongside a compute action (or '*')."""
    actions_lower = [a.lower() for a in actions if isinstance(a, str)]
    if "*" in actions_lower:
        return True
    if "iam:passrole" not in actions_lower:
        return False
    return any(a in COMPUTE_ACTIONS for a in actions_lower)


def analyze_statement(statement):
    """Return normalized fields + risk flags + privesc findings."""
    effect = statement.get("Effect", "Unknown")
    actions = normalize_to_list(statement.get("Action"))
    not_actions = normalize_to_list(statement.get("NotAction"))
    resources = normalize_to_list(statement.get("Resource"))
    not_resources = normalize_to_list(statement.get("NotResource"))
    principal = statement.get("Principal")
    has_condition = "Condition" in statement

    has_star_action = "*" in actions
    has_service_wildcard = any(
        isinstance(a, str) and a.lower().endswith(":*") for a in actions
    )
    has_star_resource = "*" in resources
    has_public_principal = principal_contains_wildcard(principal)
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
            risk_reasons.append(
                "Uses NotAction with Allow (can grant broader permissions than intended)"
            )
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
            or bool(not_resources)
        )
    )

    analysis = {
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
    analysis["privesc_findings"] = detect_privesc(analysis)
    analysis["has_passrole_and_compute"] = has_passrole_and_compute(actions)
    return analysis


def score_statement(analysis):
    """Return a severity label for a single statement."""
    if analysis["effect"] != "Allow":
        return "INFO"

    actions = analysis["actions"]
    resources = analysis["resources"]
    not_actions = analysis["not_actions"]
    not_resources = analysis["not_resources"]
    has_condition = analysis["has_condition"]

    has_star_action = "*" in actions
    has_star_resource = "*" in resources
    has_service_wildcard = any(
        isinstance(a, str) and a.lower().endswith(":*") for a in actions
    )
    has_public_principal = principal_contains_wildcard(analysis["principal"])

    if has_star_action and has_star_resource and not has_condition:
        severity = "CRITICAL"
    elif has_star_action or has_public_principal:
        severity = "HIGH"
    elif has_service_wildcard or has_star_resource or not_resources:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if analysis["privesc_findings"]:
        if analysis["has_passrole_and_compute"]:
            severity = "CRITICAL"
        elif SEVERITY_ORDER[severity] < SEVERITY_ORDER["HIGH"]:
            severity = "HIGH"

    return severity


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
    elif analysis["privesc_findings"]:
        lines.append("  Assessment: PRIVILEGE ESCALATION RISK")
    elif analysis["risk_reasons"]:
        lines.append("  Assessment: REVIEW RECOMMENDED")
    else:
        lines.append("  Assessment: looks scoped")

    if analysis["risk_reasons"]:
        lines.append("  Risk reasons:")
        for r in analysis["risk_reasons"]:
            lines.append(f"    - {r}")

    if analysis["privesc_findings"]:
        lines.append("  Privilege escalation:")
        for f in analysis["privesc_findings"]:
            lines.append(f"    - {f['action']}: {f['reason']}")
        if analysis["has_passrole_and_compute"]:
            if "*" in [a.lower() for a in analysis["actions"]]:
                lines.append(
                    "    - Wildcard Action includes iam:PassRole and compute permissions; "
                    "this may enable privilege escalation depending on the permissions "
                    "of the passed role"
                )
            else:
                lines.append(
                    "    - PassRole + compute chain detected → potential privilege-escalation path; "
                    "impact depends on the permissions of the passed role"
                )

    return "\n".join(lines)


def print_overall_summary(analyses, severities):
    """Print the final tally across all statements."""
    total = len(analyses)
    allow_count = sum(1 for a in analyses if a["effect"] == "Allow")
    deny_count = sum(1 for a in analyses if a["effect"] == "Deny")
    risky = [i + 1 for i, a in enumerate(analyses) if a["is_overly_permissive"]]
    privesc_count = sum(len(a["privesc_findings"]) for a in analyses)
    worst = highest_severity(severities)

    print("=" * 55)
    print("OVERALL SUMMARY")
    print("=" * 55)
    print(f"Total statements       : {total}")
    print(f"Allow statements       : {allow_count}")
    print(f"Deny statements        : {deny_count}")
    print(f"Overly permissive      : {len(risky)}")
    if risky:
        print(f"Risky statement #s     : {', '.join(map(str, risky))}")
    print(f"Privesc findings       : {privesc_count}")
    print(f"Highest severity       : {worst}")


def build_report(policy, policy_path, statements, analyses, severities):
    """Build a machine-readable report dict for --json output."""
    total_privesc = sum(len(a["privesc_findings"]) for a in analyses)
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
            "privesc_findings": total_privesc,
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
                "privesc_findings": analysis["privesc_findings"],
                "has_passrole_and_compute": analysis["has_passrole_and_compute"],
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
    else:
        print(f"Policy Version : {policy.get('Version', 'unknown')}")
        print(f"Statements     : {len(statements)}")
        print()

        for i, stmt in enumerate(statements, start=1):
            print(
                format_statement_summary(
                    stmt, i, analyses[i - 1], severities[i - 1]
                )
            )
            if args.verbose:
                print(
                    f"  [verbose] actions normalized: {analyses[i - 1]['actions']}"
                )
                print(
                    f"  [verbose] resources normalized: {analyses[i - 1]['resources']}"
                )
            print()

        print_overall_summary(analyses, severities)

    if any(s in ("HIGH", "CRITICAL") for s in severities):
        sys.exit(1)


if __name__ == "__main__":
    main()