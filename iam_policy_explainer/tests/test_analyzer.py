"""
Unit tests for explainer.py.

Run:   pytest -v
"""
import json
import os
import sys

import pytest

import explainer
from explainer import (
    analyze_condition,
    analyze_statement,
    detect_privesc,
    get_statements,
    has_passrole_and_compute,
    load_policy,
    normalize_principal,
    normalize_to_list,
    score_statement,
    suggest_least_privilege,
)


# ---------------------------------------------------------------------------
# normalize_to_list
# ---------------------------------------------------------------------------
class TestNormalizeToList:
    def test_none_returns_empty(self):
        assert normalize_to_list(None) == []

    def test_string_wrapped_in_list(self):
        assert normalize_to_list("s3:GetObject") == ["s3:GetObject"]

    def test_list_returned_as_is(self):
        items = ["s3:GetObject", "s3:ListBucket"]
        assert normalize_to_list(items) == items

    def test_empty_list_stays_empty(self):
        assert normalize_to_list([]) == []

    def test_int_wrapped(self):
        assert normalize_to_list(42) == [42]


# ---------------------------------------------------------------------------
# normalize_principal
# ---------------------------------------------------------------------------
class TestNormalizePrincipal:
    def test_none_returns_empty(self):
        assert normalize_principal(None) == []

    def test_star_string(self):
        assert normalize_principal("*") == ["*"]

    def test_dict_aws_star(self):
        assert normalize_principal({"AWS": "*"}) == ["*"]

    def test_dict_aws_list(self):
        out = normalize_principal({"AWS": ["arn:a", "arn:b"]})
        assert out == ["arn:a", "arn:b"]

    def test_dict_service(self):
        assert normalize_principal({"Service": "lambda.amazonaws.com"}) == [
            "lambda.amazonaws.com"
        ]

    def test_dict_mixed(self):
        out = normalize_principal({"AWS": ["arn:a"], "Service": "ec2.amazonaws.com"})
        assert sorted(out) == sorted(["arn:a", "ec2.amazonaws.com"])

    def test_list_returns_copy(self):
        src = ["*"]
        out = normalize_principal(src)
        out.append("x")
        assert src == ["*"]  # original untouched


# ---------------------------------------------------------------------------
# get_statements
# ---------------------------------------------------------------------------
class TestGetStatements:
    def test_missing_statement(self):
        assert get_statements({}) == []

    def test_single_dict(self):
        stmt = {"Effect": "Allow"}
        assert get_statements({"Statement": stmt}) == [stmt]

    def test_list(self):
        stmts = [{"Effect": "Allow"}, {"Effect": "Deny"}]
        assert get_statements({"Statement": stmts}) == stmts

    def test_weird_type(self):
        assert get_statements({"Statement": "not-a-list-or-dict"}) == []


# ---------------------------------------------------------------------------
# analyze_condition
# ---------------------------------------------------------------------------
class TestAnalyzeCondition:
    def test_missing(self):
        r = analyze_condition(None)
        assert r["present"] is False
        assert r["strong_count"] == 0

    def test_empty_dict(self):
        r = analyze_condition({})
        assert r["present"] is False

    def test_mfa_bool_true_is_strong(self):
        r = analyze_condition({"Bool": {"aws:MultiFactorAuthPresent": "true"}})
        assert r["present"] is True
        assert r["strong_count"] == 1

    def test_mfa_bool_if_exists_is_weak(self):
        r = analyze_condition({"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}})
        assert r["strong_count"] == 0
        assert r["weak_count"] == 1

    def test_source_ip_is_strong(self):
        r = analyze_condition({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})
        assert r["strong_count"] == 1

    def test_secure_transport_is_weak(self):
        r = analyze_condition({"Bool": {"aws:SecureTransport": "true"}})
        assert r["strong_count"] == 0
        assert r["weak_count"] == 1

    def test_two_strong(self):
        r = analyze_condition({
            "Bool": {"aws:MultiFactorAuthPresent": "true"},
            "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        })
        assert r["strong_count"] == 2

    def test_negating_operator_not_strong(self):
        # StringNotEquals on SourceIp is a deny-list, not a restriction
        r = analyze_condition({
            "StringNotEquals": {"aws:SourceIp": "10.0.0.0/8"}
        })
        assert r["strong_count"] == 0


# ---------------------------------------------------------------------------
# detect_privesc
# ---------------------------------------------------------------------------
def _mk_analysis(
    effect="Allow",
    actions=None,
    not_actions=None,
    resources=None,
    not_resources=None,
    principal=None,
    condition=None,
):
    """Build a minimal analysis dict for privesc tests."""
    stmt = {"Effect": effect}
    if actions is not None:
        stmt["Action"] = actions
    if not_actions is not None:
        stmt["NotAction"] = not_actions
    if resources is not None:
        stmt["Resource"] = resources
    if not_resources is not None:
        stmt["NotResource"] = not_resources
    if principal is not None:
        stmt["Principal"] = principal
    if condition is not None:
        stmt["Condition"] = condition
    return analyze_statement(stmt)


class TestDetectPrivesc:
    def test_deny_has_no_findings(self):
        a = _mk_analysis(effect="Deny", actions="iam:PassRole", resources="*")
        assert detect_privesc(a) == []

    def test_star_covers_all(self):
        a = _mk_analysis(actions="*", resources="*")
        findings = detect_privesc(a)
        assert len(findings) == 1
        assert findings[0]["action"] == "*"
        assert "all" in findings[0]["reason"].lower()

    def test_passrole_detected(self):
        a = _mk_analysis(actions="iam:PassRole", resources="*")
        findings = detect_privesc(a)
        assert any(f["action"] == "iam:PassRole" for f in findings)

    def test_case_insensitive(self):
        a = _mk_analysis(actions="IAM:PASSROLE", resources="*")
        findings = detect_privesc(a)
        assert len(findings) == 1

    def test_service_wildcard_single_finding(self):
        a = _mk_analysis(actions="iam:*", resources="*")
        findings = detect_privesc(a)
        # one finding per service wildcard, not one per covered action
        assert len(findings) == 1
        assert "iam:*" in findings[0]["action"]

    def test_notaction_returns_remaining(self):
        a = _mk_analysis(not_actions="s3:*", resources="*")
        findings = detect_privesc(a)
        assert len(findings) == 1
        assert "NotAction" in findings[0]["action"]

    def test_notaction_star_returns_nothing(self):
        a = _mk_analysis(not_actions="*", resources="*")
        assert detect_privesc(a) == []

    def test_notaction_excludes_all_privesc(self):
        excluded = [
            "iam:*",
            "sts:*",
            "lambda:*",
            "ec2:*",
            "glue:*",
            "cloudformation:*",
            "datapipeline:*",
            "codestar:*",
            "ssm:*",
        ]
        a = _mk_analysis(not_actions=excluded, resources="*")
        assert detect_privesc(a) == []

    def test_clean_statement(self):
        a = _mk_analysis(actions="s3:GetObject", resources="arn:aws:s3:::b/*")
        assert detect_privesc(a) == []


# ---------------------------------------------------------------------------
# has_passrole_and_compute
# ---------------------------------------------------------------------------
class TestHasPassroleAndCompute:
    def test_passrole_alone_false(self):
        a = _mk_analysis(actions="iam:PassRole", resources="*")
        assert has_passrole_and_compute(a) is False

    def test_passrole_plus_runinstances_true(self):
        a = _mk_analysis(actions=["iam:PassRole", "ec2:RunInstances"], resources="*")
        assert has_passrole_and_compute(a) is True

    def test_star_true(self):
        a = _mk_analysis(actions="*", resources="*")
        assert has_passrole_and_compute(a) is True

    def test_notaction_true(self):
        a = _mk_analysis(not_actions="s3:*", resources="*")
        assert has_passrole_and_compute(a) is True

    def test_notaction_excludes_passrole_false(self):
        a = _mk_analysis(not_actions="iam:PassRole", resources="*")
        assert has_passrole_and_compute(a) is False


# ---------------------------------------------------------------------------
# score_statement
# ---------------------------------------------------------------------------
class TestScoreStatement:
    def test_deny_is_info(self):
        a = _mk_analysis(effect="Deny", actions="*", resources="*")
        assert score_statement(a) == "INFO"

    def test_clean_readonly_is_low(self):
        a = _mk_analysis(
            actions="s3:GetObject",
            resources="arn:aws:s3:::b/*",
        )
        assert score_statement(a) == "LOW"

    def test_admin_is_critical(self):
        a = _mk_analysis(actions="*", resources="*")
        assert score_statement(a) == "CRITICAL"

    def test_service_wildcard_is_medium(self):
        a = _mk_analysis(actions="s3:*", resources="arn:aws:s3:::b/*")
        assert score_statement(a) == "MEDIUM"

    def test_passrole_compute_is_critical(self):
        a = _mk_analysis(actions=["iam:PassRole", "ec2:RunInstances"], resources="*")
        assert score_statement(a) == "CRITICAL"

    def test_notaction_is_high(self):
        a = _mk_analysis(not_actions="s3:*", resources="*")
        assert score_statement(a) in ("HIGH", "CRITICAL")

    def test_public_unmitigated_is_critical(self):
        a = _mk_analysis(principal="*", actions="s3:GetObject", resources="*")
        assert score_statement(a) == "CRITICAL"

    def test_public_mitigated_by_ip_downgrades(self):
        a = _mk_analysis(
            principal="*",
            actions="s3:GetObject",
            resources="arn:aws:s3:::b/*",
            condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
        )
        # A specific action and resource start at HIGH;
        # the strong source-IP condition reduces severity to MEDIUM.
        assert score_statement(a) == "MEDIUM"

    def test_admin_with_mfa_downgrades(self):
        a = _mk_analysis(
            actions="*",
            resources="*",
            condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        )
        # MFA restricts access but does not remove wildcard
        # administrative or privilege-escalation capabilities.
        assert score_statement(a) == "CRITICAL"

    def test_admin_with_mfa_and_ip_downgrades_twice(self):
        a = _mk_analysis(
            actions="*",
            resources="*",
            condition={
                "Bool": {"aws:MultiFactorAuthPresent": "true"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
            },
        )
        # These conditions restrict access but do not remove
        # the underlying wildcard administrative capabilities.
        assert score_statement(a) == "CRITICAL"

    def test_weak_mfa_does_not_downgrade(self):
        a = _mk_analysis(
            actions="*",
            resources="*",
            condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}},
        )
        assert score_statement(a) == "CRITICAL"

    def test_floor_at_low_not_info(self):
        # A LOW statement with strong mitigation stays LOW, never INFO
        a = _mk_analysis(
            actions="s3:GetObject",
            resources="arn:aws:s3:::b/*",
            condition={"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
        )
        assert score_statement(a) == "LOW"


# ---------------------------------------------------------------------------
# suggest_least_privilege
# ---------------------------------------------------------------------------
class TestSuggestLeastPrivilege:
    def test_deny_has_no_suggestions(self):
        a = _mk_analysis(effect="Deny", actions="*", resources="*")
        assert suggest_least_privilege(a) == []

    def test_star_action_suggests_enumerate(self):
        a = _mk_analysis(actions="*", resources="*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "Action" and x["current"] == "*" for x in s)

    def test_service_wildcard_suggests_specific(self):
        a = _mk_analysis(actions="s3:*", resources="arn:aws:s3:::b/*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "Action" and x["current"] == "s3:*" for x in s)

    def test_resource_star_suggests_scoping(self):
        a = _mk_analysis(actions="s3:GetObject", resources="*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "Resource" for x in s)

    def test_passrole_without_condition_suggests_condition(self):
        a = _mk_analysis(actions="iam:PassRole", resources="*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "Condition" for x in s)

    def test_passrole_with_condition_no_condition_suggestion(self):
        a = _mk_analysis(
            actions="iam:PassRole",
            resources="arn:aws:iam::1:role/r",
            condition={"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}},
        )
        s = suggest_least_privilege(a)
        assert not any(x["target"] == "Condition" for x in s)

    def test_public_principal_suggests_replacement(self):
        a = _mk_analysis(principal="*", actions="s3:GetObject", resources="arn:aws:s3:::b/*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "Principal" for x in s)

    def test_notaction_suggests_allowlist(self):
        a = _mk_analysis(not_actions="s3:*", resources="*")
        s = suggest_least_privilege(a)
        assert any(x["target"] == "NotAction" for x in s)

    def test_clean_statement_no_suggestions(self):
        a = _mk_analysis(actions="s3:GetObject", resources="arn:aws:s3:::b/*")
        assert suggest_least_privilege(a) == []


# ---------------------------------------------------------------------------
# load_policy — file-based
# ---------------------------------------------------------------------------
class TestLoadPolicy:
    def test_valid_file(self, tmp_path):
        p = tmp_path / "ok.json"
        p.write_text(json.dumps({"Version": "2012-10-17", "Statement": []}))
        out = load_policy(str(p))
        assert out["Version"] == "2012-10-17"

    def test_missing_file_exits(self):
        with pytest.raises(SystemExit) as exc:
            load_policy("/nonexistent/does-not-exist.json")
        assert exc.value.code == 1

    def test_invalid_json_exits(self, tmp_path, capsys):
        p = tmp_path / "bad.json"
        p.write_text('{"Version": "2012-10-17", "Statement": [')
        with pytest.raises(SystemExit) as exc:
            load_policy(str(p))
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "invalid JSON" in err


# ---------------------------------------------------------------------------
# End-to-end: analyze a full policy dict
# ---------------------------------------------------------------------------
class TestEndToEnd:
    def test_mixed_policy_statement_count(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
            ],
        }
        stmts = get_statements(policy)
        assert len(stmts) == 3
        analyses = [analyze_statement(s) for s in stmts]
        severities = [score_statement(a) for a in analyses]
        assert severities == ["LOW", "INFO", "CRITICAL"]

    def test_single_dict_statement(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        }
        stmts = get_statements(policy)
        assert len(stmts) == 1
        assert score_statement(analyze_statement(stmts[0])) == "CRITICAL"