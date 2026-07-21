"""Tests for the Rail base contract.

The Week-1 plan says the base class needs no tests of its own because the real
rails exercise it. That holds for the abstract `check` method — but the
`_allow` / `_block` / `_transform` helpers are actual code, and their whole
purpose is to stamp `self.name` onto every result. If that stamping broke, every
rail would produce mislabelled audit entries while still passing its own tests,
because each rail's tests check verdicts rather than names. So the helpers get
tested here.
"""

import pytest

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import Severity, Verdict


class _FakeRail(Rail):
    """A throwaway rail used only by these tests.

    Blocks anything containing "bad", rewrites anything containing "ugly", and
    allows the rest — enough to drive all three helpers without depending on a
    real rail that does not exist yet.
    """

    name = "fake"

    def check(self, text: str):
        if "bad" in text:
            return self._block("contained 'bad'", severity=Severity.HIGH, found="bad")
        if "ugly" in text:
            return self._transform(
                text.replace("ugly", "[REDACTED]"),
                "rewrote 'ugly'",
                found="ugly",
            )
        return self._allow()


# ---------------------------------------------------------------------------
# The abstract contract
# ---------------------------------------------------------------------------


def test_rail_cannot_be_instantiated_directly():
    """`Rail` is abstract; only concrete subclasses may be constructed.

    This is the payoff of @abstractmethod: the failure happens loudly at
    construction, not as an AttributeError deep inside a pipeline run.
    """
    with pytest.raises(TypeError):
        Rail()


def test_subclass_without_check_cannot_be_instantiated():
    """Forgetting to implement `check` is caught at construction time too."""

    class Incomplete(Rail):
        name = "incomplete"

    with pytest.raises(TypeError):
        Incomplete()


def test_subclass_with_check_works():
    """A complete subclass constructs normally and reports its name."""
    rail = _FakeRail()

    assert rail.name == "fake"
    assert "fake" in repr(rail)


# ---------------------------------------------------------------------------
# The result builders
# ---------------------------------------------------------------------------


def test_allow_helper_stamps_the_rail_name():
    """The reason these helpers exist: `rail` is filled in from `self.name`.

    A hand-written result would spell the name as a string literal in every
    branch of every rail, and a typo there corrupts the audit trail silently.
    """
    r = _FakeRail().check("perfectly fine text")

    assert r.verdict is Verdict.ALLOW
    assert r.rail == "fake"
    assert r.severity is Severity.LOW
    assert r.text is None


def test_block_helper_carries_reason_severity_and_metadata():
    """A block must always explain itself; severity and metadata ride along.

    Note metadata arrives via **kwargs, so a rail writes `found="bad"` rather
    than assembling a dict by hand.
    """
    r = _FakeRail().check("this is bad")

    assert r.verdict is Verdict.BLOCK
    assert r.rail == "fake"
    assert r.reason == "contained 'bad'"
    assert r.severity is Severity.HIGH
    assert r.metadata == {"found": "bad"}


def test_transform_helper_carries_the_replacement_text():
    """TRANSFORM returns the full rewritten string in `.text`.

    Not a diff, not a fragment — the pipeline assigns `.text` straight to its
    working text, and every later rail sees only the rewritten version.
    """
    r = _FakeRail().check("this is ugly")

    assert r.verdict is Verdict.TRANSFORM
    assert r.rail == "fake"
    assert r.text == "this is [REDACTED]"
    assert r.metadata == {"found": "ugly"}


def test_helpers_do_not_share_metadata_between_results():
    """Same mutable-default concern as in result.py, checked one level up.

    `**metadata` builds a fresh dict per call, so results cannot bleed into each
    other. Asserting it here means a future refactor of the helpers cannot
    quietly reintroduce sharing.
    """
    rail = _FakeRail()
    a = rail.check("clean one")
    b = rail.check("clean two")

    assert a.metadata is not b.metadata

    a.metadata["injected"] = True
    assert b.metadata == {}


def test_rail_does_not_mutate_input_text():
    """A rail returns a rewrite; it never edits the caller's text.

    Python strings are immutable so this cannot literally fail today, but the
    assertion documents the contract for any future rail that handles mutable
    input types.
    """
    original = "this is ugly"
    _FakeRail().check(original)

    assert original == "this is ugly"
