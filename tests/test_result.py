"""Tests for the result types.

These tests look almost trivially small, and that is the point. `result.py`
holds no logic — it is a set of data shapes. What can actually go wrong in a
data shape is: a default is wrong, or a mutable default is shared. So those are
exactly the two things tested here.

Run just this file:
    pytest tests/test_result.py -v
"""

from llm_bouncer.result import PipelineResult, RailResult, Severity, Verdict


# ---------------------------------------------------------------------------
# Verdict / Severity enums
# ---------------------------------------------------------------------------


def test_verdict_has_exactly_three_states():
    """Three verdicts, no more. ADR-002 rejected a two-state allow/block design.

    Asserting the exact set (rather than just checking each member exists) means
    this test fails if someone quietly adds a fourth verdict without revisiting
    the ADR and the pipeline's aggregation rule, which only handles three.
    """
    assert {v.name for v in Verdict} == {"ALLOW", "BLOCK", "TRANSFORM"}


def test_verdict_values_are_log_friendly_strings():
    """Values are lowercase strings because they get written to the JSONL audit log.

    If someone switched these to `auto()` integers, log lines would read
    `"verdict": 2` and this test would catch it.
    """
    assert Verdict.ALLOW.value == "allow"
    assert Verdict.BLOCK.value == "block"
    assert Verdict.TRANSFORM.value == "transform"


def test_severity_ranks_exist():
    """Four severity ranks, used by the audit log and the Week-3 red-team report."""
    assert {s.name for s in Severity} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# RailResult defaults
# ---------------------------------------------------------------------------


def test_railresult_requires_only_verdict_and_rail():
    """Constructing with just the two mandatory fields must work.

    Every rail builds results this way in the common ALLOW case, so if the
    signature ever drifted (a new required field added in the middle), every rail
    would break — and this test fails first, with a clear message.
    """
    r = RailResult(Verdict.ALLOW, "length")

    assert r.verdict is Verdict.ALLOW
    assert r.rail == "length"


def test_railresult_defaults_are_the_quiet_ones():
    """An unspecified result should be as un-alarming as possible.

    reason="" (nothing to explain), severity=LOW (do not page anyone), text=None
    (no rewrite happened), metadata={} (no detail collected). A rail must
    deliberately opt in to raising severity — the default never does it by
    accident.
    """
    r = RailResult(Verdict.ALLOW, "length")

    assert r.reason == ""
    assert r.severity is Severity.LOW
    assert r.text is None
    assert r.metadata == {}


# ---------------------------------------------------------------------------
# The mutable-default trap — the reason this test file exists
# ---------------------------------------------------------------------------


def test_two_railresults_do_not_share_one_metadata_dict():
    """Each RailResult must own a private metadata dict.

    THE TEST THAT MATTERS. If `metadata` had been declared as `= {}` instead of
    `field(default_factory=dict)`, Python would evaluate that `{}` exactly once
    at class-definition time and hand the same object to every instance. Then
    the LengthRail stashing its measurement would corrupt the InjectionRail's
    result, because they would be the identical dict in memory.

    Two assertions, and they are not redundant:

      `is not`  — identity. Proves they are genuinely different objects. This is
                  the assertion that directly detects the shared-default bug.

      mutate-then-check — behaviour. Proves the consequence a user would actually
                  notice. Even if some future refactor made identity pass by
                  accident (say, a copy-on-read wrapper), this still catches
                  real-world bleed between results.

    Identity alone is the tighter check; the behavioural half is what makes the
    failure message obvious to whoever breaks it a year from now.
    """
    a = RailResult(Verdict.ALLOW, "length")
    b = RailResult(Verdict.ALLOW, "injection")

    assert a.metadata is not b.metadata

    a.metadata["length"] = 5210
    assert b.metadata == {}, "metadata leaked between RailResult instances"


def test_railresult_metadata_accepts_rail_specific_detail():
    """Explicitly passed metadata is kept as-is — the normal rail usage."""
    r = RailResult(
        Verdict.BLOCK,
        "length",
        reason="length 5210 > max 4000",
        severity=Severity.LOW,
        metadata={"length": 5210, "max_len": 4000},
    )

    assert r.metadata == {"length": 5210, "max_len": 4000}
    assert r.reason == "length 5210 > max 4000"


def test_railresult_carries_rewritten_text_on_transform():
    """TRANSFORM is the verdict that uses `text`; nothing else sets it.

    The pipeline reads `.text` only inside its TRANSFORM branch, so this field
    being populated is the whole contract between a redacting rail and the
    pipeline.
    """
    r = RailResult(
        Verdict.TRANSFORM,
        "secrets",
        reason="redacted 1 api key",
        severity=Severity.HIGH,
        text="my key is [REDACTED]",
    )

    assert r.verdict is Verdict.TRANSFORM
    assert r.text == "my key is [REDACTED]"


# ---------------------------------------------------------------------------
# PipelineResult
# ---------------------------------------------------------------------------


def test_pipelineresult_clean_run_carries_final_text():
    """Nothing blocked: blocked=False, text present, no blocking result."""
    allowed = RailResult(Verdict.ALLOW, "length")
    p = PipelineResult(
        blocked=False,
        final_text="hello",
        blocking=None,
        results=[allowed],
    )

    assert p.blocked is False
    assert p.final_text == "hello"
    assert p.blocking is None
    assert p.results == [allowed]


def test_pipelineresult_blocked_run_has_no_final_text():
    """Blocked runs must return final_text=None, never the offending string.

    This is a safety property, not a style choice. If a blocked pipeline still
    handed back the text, a caller who forgot to check `.blocked` would forward
    hostile input straight to the model. None makes that mistake raise a
    TypeError instead of quietly leaking.
    """
    hit = RailResult(Verdict.BLOCK, "injection", reason="pattern: ignore previous")
    p = PipelineResult(blocked=True, final_text=None, blocking=hit, results=[hit])

    assert p.blocked is True
    assert p.final_text is None
    assert p.blocking is hit


def test_two_pipelineresults_do_not_share_one_results_list():
    """Same mutable-default trap as RailResult.metadata, this time with a list.

    A shared list default would be worse than the dict one: results would
    accumulate across every pipeline run for the lifetime of the process, so an
    audit log would attribute one user's blocked injection to another user's
    clean request.
    """
    a = PipelineResult(blocked=False, final_text="a", blocking=None)
    b = PipelineResult(blocked=False, final_text="b", blocking=None)

    assert a.results is not b.results

    a.results.append(RailResult(Verdict.ALLOW, "length"))
    assert b.results == [], "results leaked between PipelineResult instances"
