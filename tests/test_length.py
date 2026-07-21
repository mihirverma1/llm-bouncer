"""Tests for LengthRail.

The rail has one comparison in it, which makes the interesting tests the ones
around the boundary and the constructor rather than the obvious pass/fail cases.

A note on style: these tests build strings with `"x" * n` rather than pasting
literal text. The rail counts characters and does not care what they are, so
generated strings state the intent ("exactly 10 characters") far more clearly
than a hand-written sentence somebody would have to count.
"""

import pytest

from llm_bouncer.rails.length import LengthRail
from llm_bouncer.result import Severity, Verdict


# ---------------------------------------------------------------------------
# The three cases the spec names
# ---------------------------------------------------------------------------


def test_text_over_the_limit_is_blocked():
    rail = LengthRail(max_len=10)

    result = rail.check("x" * 11)

    assert result.verdict is Verdict.BLOCK
    assert result.rail == "length"
    assert result.severity is Severity.LOW


def test_text_under_the_limit_is_allowed():
    rail = LengthRail(max_len=10)

    result = rail.check("x" * 9)

    assert result.verdict is Verdict.ALLOW
    assert result.rail == "length"


def test_text_exactly_at_the_limit_is_allowed():
    """The boundary case, pinned deliberately.

    The rail compares with `>`, so `max_len` characters is fine and `max_len + 1`
    is not. `max_len` means "the maximum permitted length"; a maximum you may not
    actually reach would be a strange thing to call a maximum.

    This test exists so that reading `>` versus `>=` in the source is never
    required to answer the question, and so nobody can flip it during a refactor
    without a test turning red. Off-by-one at a boundary is the classic silent
    bug: `max_len=4000` quietly permitting only 3999 would go unnoticed for
    months.
    """
    rail = LengthRail(max_len=10)

    assert rail.check("x" * 10).verdict is Verdict.ALLOW
    assert rail.check("x" * 11).verdict is Verdict.BLOCK


# ---------------------------------------------------------------------------
# What the result carries
# ---------------------------------------------------------------------------


def test_block_reason_states_both_numbers():
    """The reason must answer "by how much?" — it lands in the audit log.

    Asserting the exact string is intentional. It is a user-facing artifact that
    ends up in logs and red-team reports, so changing it should be a deliberate
    act that updates a test, not an incidental edit.
    """
    rail = LengthRail(max_len=10)

    result = rail.check("x" * 25)

    assert result.reason == "length 25 > max 10"


def test_block_metadata_carries_measurement_and_limit():
    """Structured detail for the audit log, alongside the human-readable reason.

    A log consumer can filter on `metadata["length"]` numerically; it cannot do
    arithmetic on a sentence.
    """
    rail = LengthRail(max_len=10)

    result = rail.check("x" * 25)

    assert result.metadata == {"length": 25, "max_len": 10}


def test_allow_also_carries_measurement():
    """Metadata on the ALLOW path too, which is what makes the log useful for tuning.

    Blocked requests only ever tell you about traffic above the cap. Recording
    lengths that passed is how you learn that real traffic peaks at 900
    characters and a 4000 cap has plenty of headroom.
    """
    rail = LengthRail(max_len=10)

    result = rail.check("x" * 4)

    assert result.metadata == {"length": 4, "max_len": 10}


def test_block_sets_no_replacement_text():
    """BLOCK is not TRANSFORM — `text` stays None.

    LengthRail could in principle truncate and return TRANSFORM, and that is
    deliberately not done: silently truncating changes the user's meaning, and
    an attacker could exploit the cut point to strip a trailing instruction.
    Refusing is honest; truncating is a guess.
    """
    rail = LengthRail(max_len=10)

    assert rail.check("x" * 25).text is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_string_is_allowed():
    """Zero characters cannot exceed a positive limit.

    Whether empty input is *acceptable* is a different question, and not this
    rail's to answer — it measures size and nothing else. One rail, one concern.
    """
    assert LengthRail(max_len=10).check("").verdict is Verdict.ALLOW


def test_length_is_counted_in_characters_not_bytes():
    """`len()` on a Python str counts characters, so non-ASCII text is not penalised.

    "héllo wörld" is 11 characters but 13 bytes in UTF-8. Counting bytes would
    make the effective limit depend on the user's language — tighter for anyone
    writing Hindi, Japanese, or emoji. Characters are the fairer unit here.

    (Neither is tokens, which is what actually gets billed. Character count is a
    cheap proxy that needs no tokenizer and no model-specific dependency. A
    token-aware rail could be added later as its own rail.)
    """
    text = "héllo wörld"

    assert len(text) == 11
    assert LengthRail(max_len=11).check(text).verdict is Verdict.ALLOW


def test_multiline_text_counts_newlines():
    """Newlines are characters like any other — nothing is stripped first.

    Worth pinning: a pasted document is mostly whitespace by volume, and a rail
    that quietly ignored it would have a much looser real limit than advertised.
    """
    text = "a\nb\nc"

    assert len(text) == 5
    assert LengthRail(max_len=5).check(text).verdict is Verdict.ALLOW
    assert LengthRail(max_len=4).check(text).verdict is Verdict.BLOCK


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_zero_max_len_is_rejected():
    """`max_len=0` would block every request, including empty ones.

    This is the one place a rail is allowed to raise. The "never raise on hostile
    input" rule protects against attacker-controlled *text*; a bad constructor
    argument is a programmer mistake, and failing at startup beats a silent
    outage where everything is blocked and nobody knows why.
    """
    with pytest.raises(ValueError):
        LengthRail(max_len=0)


def test_negative_max_len_is_rejected():
    with pytest.raises(ValueError):
        LengthRail(max_len=-1)


def test_non_integer_max_len_is_rejected():
    with pytest.raises(ValueError):
        LengthRail(max_len="4000")


def test_bool_max_len_is_rejected():
    """`bool` subclasses `int` in Python, so `True` would pass a naive isinstance check.

    `LengthRail(max_len=True)` would silently become a one-character limit — most
    likely from someone mixing up a feature flag with a value. The rail checks
    for `bool` explicitly to catch it.
    """
    with pytest.raises(ValueError):
        LengthRail(max_len=True)


# ---------------------------------------------------------------------------
# Contract conformance
# ---------------------------------------------------------------------------


def test_rail_is_reusable_across_calls():
    """One instance, many checks, no state carried between them.

    LengthRail holds only configuration, no per-request state, so results cannot
    bleed across calls. Rate limiting (a later task) will introduce genuine
    state, and this test is the baseline to compare against when it does.
    """
    rail = LengthRail(max_len=10)

    first = rail.check("x" * 25)
    second = rail.check("ok")

    assert first.verdict is Verdict.BLOCK
    assert second.verdict is Verdict.ALLOW
    assert first.metadata == {"length": 25, "max_len": 10}
    assert second.metadata == {"length": 2, "max_len": 10}
