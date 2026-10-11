import argparse
import json
import ipaddress
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
SEVERITY_LADDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# These keys can narrow the set of principals or network locations, but only
# when paired with a restrictive operator and a meaningful value.
STRONG_CONDITION_KEYS = {
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:principalorgid",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:principalarn",
}
RESTRICTING_OPERATORS = {
    "IpAddress",
    "StringEquals",
    "StringLike",
    "ArnEquals",
    "ArnLike",
    "StringEqualsIgnoreCase",
}


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

def normalize_principal(principal):
    """Flatten an IAM Principal into a list of principal values."""
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, list):
        return list(principal)
    if isinstance(principal, dict):
        values = []
        for value in principal.values():
            if isinstance(value, list):
                values.extend(value)
            else:
                values.append(value)
        return values
    return [principal]


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


def _condition_values_are_restrictive(key, operator, value):
    """Conservatively decide whether a condition value meaningfully narrows access."""
    values = value if isinstance(value, list) else [value]
    if not values:
        return False

    for item in values:
        if not isinstance(item, (str, int, float)):
            return False
        text = str(item).strip()
        if not text or "*" in text:
            return False

        if key.lower() == "aws:sourceip":
            try:
                network = ipaddress.ip_network(text, strict=False)
                if network.prefixlen == 0:
                    return False
            except ValueError:
                return False

    return True


def analyze_condition(condition):
    """Summarize recognized IAM condition mitigations without validating IAM syntax."""
    result = {
        "present": isinstance(condition, dict) and bool(condition),
        "mitigations": [],
        "strong_count": 0,
        "weak_count": 0,
        "raw": condition,
    }
    if not result["present"]:
        return result

    for operator, key_values in condition.items():
        if not isinstance(operator, str) or not isinstance(key_values, dict):
            continue
        for key, value in key_values.items():
            if not isinstance(key, str):
                continue
            key_lower = key.lower()
            operator_is_restricting = operator in RESTRICTING_OPERATORS
            value_is_restrictive = _condition_values_are_restrictive(
                key, operator, value
            )

            if key_lower == "aws:multifactorauthpresent":
                value_text = str(value).lower()
                if operator == "Bool" and value_text == "true":
                    result["mitigations"].append({
                        "key": key,
                        "operator": operator,
                        "strength": "strong",
                        "reason": "Requires MFA",
                    })
                    result["strong_count"] += 1
                elif operator == "BoolIfExists" and value_text == "true":
                    result["mitigations"].append({
                        "key": key,
                        "operator": operator,
                        "strength": "weak",
                        "reason": "MFA check uses BoolIfExists and may not constrain requests when the key is absent",
                    })
                    result["weak_count"] += 1

            elif key_lower in STRONG_CONDITION_KEYS:
                if operator_is_restricting and value_is_restrictive:
                    result["mitigations"].append({
                        "key": key,
                        "operator": operator,
                        "strength": "strong",
                        "reason": f"Restricts access using {key} and {operator}",
                    })
                    result["strong_count"] += 1

            elif key_lower == "aws:securetransport":
                if operator == "Bool" and str(value).lower() == "true":
                    result["mitigations"].append({
                        "key": key,
                        "operator": operator,
                        "strength": "weak",
                        "reason": "Requires secure transport; this protects transport, not principal scope",
                    })
                    result["weak_count"] += 1

    return result


def detect_privesc(analysis):
    """Return list of {action, reason} for privesc actions in this statement."""
    if analysis["effect"] != "Allow":
        return []

    actions = analysis["actions"]
    not_actions = analysis["not_actions"]

    # NotAction means every action except the excluded set. Treat this as a
    # static heuristic: report known privilege-escalation actions that remain
    # possible rather than claiming the exact effective permission set.
    if not_actions:
        not_lower = [a.lower() for a in not_actions if isinstance(a, str)]
        if "*" in not_lower:
            return []

        excluded = set()
        for not_action in not_lower:
            if not_action in PRIVESC_ACTIONS:
                excluded.add(not_action)
            elif not_action.endswith(":*"):
                service_prefix = not_action.split(":")[0] + ":"
                excluded.update(
                    action
                    for action in PRIVESC_ACTIONS
                    if action.startswith(service_prefix)
                )

        remaining = set(PRIVESC_ACTIONS) - excluded
        if remaining:
            return [{
                "action": f"NotAction: {', '.join(map(str, not_actions))}",
                "reason": (
                    "Allow with NotAction may still permit known privilege-escalation "
                    f"actions; {len(remaining)} known action(s) remain possible"
                ),
            }]
        return []

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


def has_passrole_and_compute(analysis):
    """True if PassRole and at least one compute action can both be allowed."""
    actions_lower = [
        a.lower() for a in analysis["actions"] if isinstance(a, str)
    ]
    not_actions_lower = [
        a.lower() for a in analysis["not_actions"] if isinstance(a, str)
    ]

    if analysis["not_actions"]:
        if "*" in not_actions_lower:
            return False

        def excluded(action):
            service = action.split(":")[0] + ":"
            return any(
                item == action or item == service + "*"
                for item in not_actions_lower
            )

        passrole_allowed = not excluded("iam:passrole")
        compute_allowed = any(
            not excluded(action) for action in COMPUTE_ACTIONS
        )
        return passrole_allowed and compute_allowed

    if "*" in actions_lower:
        return True

    if "iam:passrole" not in actions_lower:
        return False

    return any(action in COMPUTE_ACTIONS for action in actions_lower)


def analyze_statement(statement):
    """Return normalized fields, condition analysis, risk flags and findings."""
    effect = statement.get("Effect", "Unknown")
    actions = normalize_to_list(statement.get("Action"))
    not_actions = normalize_to_list(statement.get("NotAction"))
    resources = normalize_to_list(statement.get("Resource"))
    not_resources = normalize_to_list(statement.get("NotResource"))
    principal = statement.get("Principal")
    principals = normalize_principal(principal)
    condition_analysis = analyze_condition(statement.get("Condition"))
    has_condition = condition_analysis["present"]

    has_star_action = any(isinstance(a, str) and a == "*" for a in actions)
    has_service_wildcard = any(
        isinstance(a, str) and a.lower().endswith(":*") for a in actions
    )
    has_star_resource = any(isinstance(r, str) and r == "*" for r in resources)
    has_public_principal = principal_contains_wildcard(principal)

    not_actions_lower = [
        a.lower() for a in not_actions if isinstance(a, str)
    ]
    # An Allow statement with NotAction:"*" has no effective allowed actions.
    no_effective_actions = "*" in not_actions_lower

    has_wildcard = (
        has_star_action
        or has_service_wildcard
        or has_star_resource
        or bool(not_actions)
        or bool(not_resources)
    )

    risk_reasons = []
    if effect == "Allow" and not no_effective_actions:
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
        if has_public_principal and condition_analysis["strong_count"] == 0:
            risk_reasons.append(
                "Principal contains '*' with no recognized strong restriction — potentially public"
            )
        elif has_public_principal:
            risk_reasons.append(
                "Principal contains '*' but a recognized Condition restricts access; verify the guardrail"
            )

    has_broad_not_action = bool(not_actions) and not no_effective_actions
    is_overly_permissive = (
        effect == "Allow"
        and not no_effective_actions
        and (
            has_star_action
            or has_service_wildcard
            or has_star_resource
            or has_broad_not_action
            or bool(not_resources)
        )
    )
    # A wildcard principal on a no-action statement is not effective public access.
    is_public = effect == "Allow" and has_public_principal and not no_effective_actions

    analysis = {
        "effect": effect,
        "actions": actions,
        "not_actions": not_actions,
        "resources": resources,
        "not_resources": not_resources,
        "principal": principal,
        "principals": principals,
        "is_public": is_public,
        "has_condition": has_condition,
        "condition": condition_analysis,
        "no_effective_actions": no_effective_actions,
        "risk_reasons": risk_reasons,
        "is_overly_permissive": is_overly_permissive,
    }
    analysis["privesc_findings"] = detect_privesc(analysis)
    analysis["has_passrole_and_compute"] = has_passrole_and_compute(analysis)
    return analysis



def _downgrade(severity, levels):
    """Lower severity by N levels, with a floor of LOW."""
    if severity not in SEVERITY_LADDER:
        return severity
    index = SEVERITY_LADDER.index(severity)
    return SEVERITY_LADDER[max(1, index - levels)]


def score_statement(analysis):
    """Return a heuristic severity label for a single statement."""
    if analysis["effect"] != "Allow":
        return "INFO"

    if analysis["no_effective_actions"]:
        return "LOW"

    actions = analysis["actions"]
    resources = analysis["resources"]
    not_resources = analysis["not_resources"]
    strong_mitigations = analysis["condition"]["strong_count"]

    has_star_action = any(isinstance(a, str) and a == "*" for a in actions)
    has_star_resource = any(isinstance(r, str) and r == "*" for r in resources)
    has_service_wildcard = any(
        isinstance(a, str) and a.lower().endswith(":*") for a in actions
    )

    if (
        analysis["is_public"]
        and (has_star_action or has_star_resource)
        and strong_mitigations == 0
    ):
        severity = "CRITICAL"
    elif has_star_action and has_star_resource and strong_mitigations == 0:
        severity = "CRITICAL"
    elif has_star_action or analysis["is_public"] or analysis["not_actions"]:
        severity = "HIGH"
    elif has_service_wildcard or has_star_resource or not_resources:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Conditions do not erase privilege-escalation capability for callers who
    # satisfy them, so do not downgrade a statement with privesc findings.
    if analysis["privesc_findings"]:
        if analysis["has_passrole_and_compute"]:
            severity = "CRITICAL"
        elif SEVERITY_ORDER[severity] < SEVERITY_ORDER["HIGH"]:
            severity = "HIGH"
        return severity

    # A recognized condition can reduce exposure, but it does not narrow a
    # wildcard Action/Resource or neutralize privilege-escalation capability.
    # Apply at most a one-level downgrade only when the statement is otherwise
    # scoped; this is a heuristic, not AWS policy validation.
    broad_scope = (
        has_star_action
        or has_star_resource
        or has_service_wildcard
        or bool(not_resources)
        or bool(analysis["not_actions"])
    )
    if strong_mitigations > 0 and not broad_scope:
        severity = _downgrade(severity, 1)

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

    if analysis["principals"]:
        lines.append(
            f"  Principal: {', '.join(map(str, analysis['principals']))}"
        )

    lines.append(f"  Condition: {'yes' if analysis['has_condition'] else 'no'}")

    if analysis["is_public"]:
        if analysis["condition"]["strong_count"]:
            lines.append("  Public access: YES but restricted by recognized Condition (verify guardrail)")
        else:
            lines.append("  Public access: YES (Principal contains '*', no recognized strong restriction)")

    if analysis["condition"]["mitigations"]:
        lines.append("  Condition mitigations:")
        for mitigation in analysis["condition"]["mitigations"]:
            lines.append(
                f"    - [{mitigation['strength']}] {mitigation['operator']} "
                f"{mitigation['key']}: {mitigation['reason']}"
            )

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

    risky = [
        i + 1
        for i, a in enumerate(analyses)
        if a["is_overly_permissive"]
    ]

    public = [
        i + 1
        for i, a in enumerate(analyses)
        if a["is_public"]
    ]

    public_without_strong = [
        i + 1
        for i, a in enumerate(analyses)
        if a["is_public"] and a["condition"]["strong_count"] == 0
    ]

    public_with_strong = [
        i + 1
        for i, a in enumerate(analyses)
        if a["is_public"] and a["condition"]["strong_count"] > 0
    ]

    privesc_count = sum(
        len(a["privesc_findings"]) for a in analyses
    )

    mitigated = [
        i + 1
        for i, a in enumerate(analyses)
        if a["condition"]["strong_count"] > 0
    ]

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

    print(f"Wildcard principal     : {len(public)}")
    if public:
        print(f"Wildcard statement #s  : {', '.join(map(str, public))}")

    print(f"Without strong restriction: {len(public_without_strong)}")
    if public_without_strong:
        print(
            "Potentially unrestricted #s: "
            + ", ".join(map(str, public_without_strong))
        )

    print(f"With strong condition  : {len(public_with_strong)}")
    if public_with_strong:
        print(
            "Conditioned statement #s: "
            + ", ".join(map(str, public_with_strong))
        )

    print(f"With strong mitigations: {len(mitigated)}")
    if mitigated:
        print(f"Mitigated statement #s : {', '.join(map(str, mitigated))}")

    print(f"Privesc findings       : {privesc_count}")
    print(f"Highest severity       : {worst}")


def build_report(policy, policy_path, statements, analyses, severities):
    """Build a machine-readable report dict for --json output."""
    total_privesc = sum(len(a["privesc_findings"]) for a in analyses)
    public_count = sum(1 for a in analyses if a["is_public"])
    mitigated_count = sum(1 for a in analyses if a["condition"]["strong_count"] > 0)
    return {
        "file": policy_path,
        "version": policy.get("Version", "unknown"),
        "summary": {
            "total_statements": len(statements),
            "allow": sum(1 for a in analyses if a["effect"] == "Allow"),
            "deny": sum(1 for a in analyses if a["effect"] == "Deny"),
            "overly_permissive": sum(1 for a in analyses if a["is_overly_permissive"]),
            "public_access": public_count,
            "with_strong_mitigations": mitigated_count,
            "privesc_findings": total_privesc,
            "highest_severity": highest_severity(severities),
            "wildcard_principal_statements": sum(
                1 for a in analyses if a["is_public"]
            ),
            "wildcard_principal_without_strong_condition": sum(
                1
                for a in analyses
                if a["is_public"] and a["condition"]["strong_count"] == 0
            ),
            "wildcard_principal_with_strong_condition": sum(
                1
                for a in analyses
                if a["is_public"] and a["condition"]["strong_count"] > 0
            ),
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
                "principals": analysis["principals"],
                "is_public": analysis["is_public"],
                "has_condition": analysis["has_condition"],
                "condition_mitigations": analysis["condition"]["mitigations"],
                "condition_strong_count": analysis["condition"]["strong_count"],
                "condition_weak_count": analysis["condition"]["weak_count"],
                "no_effective_actions": analysis["no_effective_actions"],
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
    if not isinstance(policy.get("Statement"), (dict, list, type(None))):
        print("Error: IAM policy 'Statement' must be an object or array", file=sys.stderr)
        sys.exit(1)
    if any(not isinstance(statement, dict) for statement in statements):
        print("Error: every IAM policy statement must be a JSON object", file=sys.stderr)
        sys.exit(1)

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
                print(
                    f"  [verbose] principals normalized: {analyses[i - 1]['principals']}"
                )
                print(
                    f"  [verbose] condition strong/weak: "
                    f"{analyses[i - 1]['condition']['strong_count']}/"
                    f"{analyses[i - 1]['condition']['weak_count']}"
                )
            print()

        print_overall_summary(analyses, severities)

    if any(s in ("HIGH", "CRITICAL") for s in severities):
        sys.exit(1)


if __name__ == "__main__":
    main()