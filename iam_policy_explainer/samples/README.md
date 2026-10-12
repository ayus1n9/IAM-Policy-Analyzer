# Sample Policies

Each file demonstrates a specific detection path. Run any with:

```bash
python3 explainer.py samples/<file>.json
```

| File | What it shows | Expected severity |
|---|---|---|
| `test.json` | Scoped read-only S3 — the "clean" baseline | LOW, exit 0 |
| `admin.json` | `Action: *` + `Resource: *`, no condition | CRITICAL, exit 1 |
| `allow_s3_all.json` | `s3:*` on `Resource: *` | MEDIUM |
| `mixed.json` | Allow + Deny + NotAction in one policy | HIGH (worst statement) |
| `single_statement.json` | `Statement` as a single dict, not a list | LOW |
| `privesc.json` | `iam:PassRole` + `ec2:RunInstances` chain; `iam:CreatePolicyVersion`; `sts:AssumeRole` | CRITICAL |
| `public_bucket.json` | Resource policy with `Principal: *` and unmitigated public read/write statements | HIGH |
| `notaction_allowall.json` | `NotAction` inverse logic, including `NotAction: *` | HIGH |
| `mfa_admin.json` | Broad admin policies with strong MFA/IP conditions and a weak MFA condition; broad scope and privilege-escalation findings prevent severity downgrades | CRITICAL |
| `ip_restricted_bucket.json` | Public bucket restricted by `aws:SourceIp`, plus weakly-mitigated variants | LOW–CRITICAL |
| `suggestions_demo.json` | One statement per suggestion rule | varies |
| `broken.json` | Deliberately invalid JSON — tests the error path | exit 1 |
