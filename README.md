# IAM Policy Reader

Read a local AWS IAM policy JSON file and print a security summary: severity
scoring, privilege-escalation detection, public-access flags, condition
mitigations, and least-privilege suggestions. No AWS account or credentials
needed — pure static analysis of the policy document.

## What it detects

| Category | Examples |
|---|---|
| **Wildcards** | `Action: *`, `s3:*`, `Resource: *` |
| **Privilege escalation** | `iam:PassRole` + compute chains, `iam:CreatePolicyVersion`, `sts:AssumeRole`, and ~25 more |
| **Public access** | `Principal: *` in resource policies |
| **Deny-list patterns** | `NotAction` / `NotResource` with `Allow` |
| **Mitigations** | Recognizes `aws:MultiFactorAuthPresent`, `aws:SourceIp`, `aws:PrincipalOrgID`, etc., and downgrades severity accordingly |
| **Least-privilege hints** | Suggests concrete narrower actions, resources, and conditions |

## Severity scale

| Label | Meaning |
|---|---|
| `INFO` | Deny statement — restrictive, not risky |
| `LOW` | Scoped actions and resources, no wildcards |
| `MEDIUM` | Service wildcard (`s3:*`), `Resource: *`, or `NotResource` |
| `HIGH` | `Action: *`, `NotAction` with Allow, public principal without mitigation, or a standalone privesc action |
| `CRITICAL` | `Action: *` + `Resource: *` without Condition; public + broad; or `iam:PassRole` chained with a compute action |

Recognized strong conditions can reduce severity by one level for qualifying
statements. Broadly scoped statements and statements with privilege-escalation
findings are not downgraded by these mitigations. This is heuristic analysis,
not full AWS IAM policy validation.

## Install

Stdlib only at runtime. Dev dependency: `pytest`.

```bash
cd iam_policy_explainer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # only needed to run tests
```

## Usage

```bash
# Human-readable summary
python3 explainer.py samples/admin.json

# Include normalized field dumps
python3 explainer.py samples/privesc.json --verbose

# Machine-readable JSON (pipe into jq, CI, etc.)
python3 explainer.py samples/public_bucket.json --json | jq .summary

# Show version
python3 explainer.py --version

# Full help with examples
python3 explainer.py -h
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No `HIGH` or `CRITICAL` findings |
| `1` | At least one `HIGH` or `CRITICAL` finding, or input error (missing file, invalid JSON) |
| `2` | CLI usage error (missing argument, unknown flag) — from argparse |

Useful in CI:

```bash
python3 explainer.py policy.json && deploy.sh
```

`deploy.sh` only runs if the policy is safe.

## JSON output shape

```json
{
  "file": "samples/admin.json",
  "version": "2012-10-17",
  "summary": {
    "total_statements": 1,
    "allow": 1,
    "deny": 0,
    "overly_permissive": 1,
    "public_access": 0,
    "with_strong_mitigations": 0,
    "privesc_findings": 1,
    "suggestions": 2,
    "highest_severity": "CRITICAL"
  },
  "statements": [
    {
      "index": 1,
      "sid": "FullAdmin",
      "effect": "Allow",
      "severity": "CRITICAL",
      "actions": ["*"],
      "resources": ["*"],
      "is_public": false,
      "has_condition": false,
      "is_overly_permissive": true,
      "risk_reasons": ["..."],
      "privesc_findings": [{"action": "*", "reason": "..."}],
      "has_passrole_and_compute": true,
      "suggestions": [{"target": "Action", "current": "*", "suggestion": "..."}]
    }
  ]
}
```

## Sample gallery

See `samples/README.md` for a description of every test policy.

Quick tour:

```bash
python3 explainer.py samples/test.json                # LOW, exit 0
python3 explainer.py samples/admin.json               # CRITICAL, exit 1
python3 explainer.py samples/privesc.json             # CRITICAL via PassRole chain
python3 explainer.py samples/public_bucket.json       # public access
python3 explainer.py samples/mfa_admin.json           # broad admin; mitigations don't downgrade
python3 explainer.py samples/suggestions_demo.json    # one of each finding type
```

## Tests

```bash
pytest -v
```

64 tests covering normalization, severity scoring, privilege-escalation
detection, condition analysis, policy loading, and end-to-end analysis.

## Design notes

- **Stdlib-only runtime.** No `boto3`, no network calls.
- **Case-insensitive action matching.** `IAM:PassRole` == `iam:passrole`.
- **Statement polymorphism handled.** `Statement` may be a single dict or a list.
- **Principal polymorphism handled.** `"*"`, `{"AWS": "*"}`, `{"AWS": [...]}`, `{"Service": ...}` all normalize to a flat list.
- **Conditions are advisory.** Mitigations reduce severity but never hide a finding entirely.

## Limitations

- No evaluation of `NotPrincipal` yet.
- Condition evaluation is key-based, not a full policy simulator.
- Assumes a single policy document (no policy sets or permission boundaries).
- Privesc table is curated from public research (Rhino Security, IAM Vulnerable) — not exhaustive.
