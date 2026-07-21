"""Result types shared by every rail and the pipeline.

This module is deliberately the first thing built, because everything else in
llm-bouncer depends on it. A rail's only job is to return a `RailResult`; the
pipeline's only job is to run rails and fold their results into a
`PipelineResult`. Get these four types right and the rest of the library is
mechanical.

Design source: docs/superpowers/specs/2026-07-20-llm-bouncer-week1-design.md
(ADR-002 — verdict type). The `RailResult` field list below is fixed by that
ADR; do not add or rename fields without updating the ADR first.
"""

from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    """What a rail decided about a piece of text.

    Three states, not two. A plain allow/block pair cannot express a rail that
    *rewrites* input rather than rejecting it — for example redacting an API key
    out of a prompt while letting the rest through. That case is common enough
    (PII redaction now, Week-2 context neutralization later) that bolting it on
    afterwards would mean a breaking redesign. So TRANSFORM exists from day one.

    The values are lowercase strings rather than `auto()` integers on purpose:
    they get written into the JSONL audit log, and `"block"` is readable in a log
    file while `2` is not. Access the string with `Verdict.BLOCK.value`.
    """

    ALLOW = "allow"
    """Text is clean. Pass it to the next rail unchanged."""

    BLOCK = "block"
    """Text is hostile or oversized. Pipeline stops here; nothing downstream runs."""

    TRANSFORM = "transform"
    """Text is salvageable but must be rewritten first. The replacement text is
    carried in `RailResult.text`, and the pipeline uses it for every later rail."""


class Severity(Enum):
    """How alarming a non-ALLOW verdict is.

    Severity is *reporting* metadata, not control flow — the pipeline blocks on
    a BLOCK verdict regardless of whether it is LOW or CRITICAL. What severity
    drives is triage: the Week-3 red-team report ranks findings by it, and an
    operator watching the audit log wants to know the difference between "user
    pasted a 5MB blob" (LOW) and "user tried to exfiltrate the system prompt"
    (CRITICAL).

    Same string-value reasoning as Verdict: these land in the audit log.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RailResult:
    """One rail's verdict on one piece of text.

    Every rail returns exactly this type — that uniformity is what lets the
    pipeline treat rails as interchangeable and lets the audit logger write one
    line per check without knowing which rail spoke.

    Field order matters: `verdict` and `rail` have no defaults, so they are
    positional and required. Python forbids a field without a default following
    one with a default, which is why the two mandatory fields come first.
    """

    verdict: Verdict
    """The decision. Required."""

    rail: str
    """Which rail spoke, e.g. "length", "injection", "secrets". Required.

    A plain string rather than an enum, because third parties will write their
    own rails and must not have to patch a library enum to name them.
    """

    reason: str = ""
    """Human-readable explanation of the verdict.

    Feeds two consumers: the audit log (so an operator can tell *why* a request
    died) and the red-team report (so a finding reads as a sentence). Keep it
    short and factual — "length 5210 > max 4000", not "input too long maybe?".
    """

    severity: Severity = Severity.LOW
    """Triage rank. Defaults to LOW so a rail must opt in to alarming anyone.

    Note this default is safe to write inline, unlike `metadata` below: enum
    members are immutable singletons, so every RailResult sharing the identical
    `Severity.LOW` object is harmless — nobody can mutate it.
    """

    text: str | None = None
    """The rewritten text. Set ONLY when verdict is TRANSFORM; None otherwise.

    Kept as one nullable field rather than a separate TransformResult subclass so
    the pipeline never has to type-check what came back — it reads `.verdict`,
    and only looks at `.text` in the TRANSFORM branch.
    """

    metadata: dict = field(default_factory=dict)
    """Rail-specific detail: matched pattern, entropy score, measured length.

    THE IMPORTANT LINE IN THIS FILE. It uses `field(default_factory=dict)` and
    not `metadata: dict = {}`, and the reason is the single nastiest beginner
    trap in Python:

        Default values are evaluated ONCE, when the class is defined — not once
        per instance.

    Had this been written `= {}`, that one dict object would be created a single
    time at import and then *shared by every RailResult ever constructed*. The
    LengthRail writing `metadata["length"] = 5210` would silently appear inside
    the InjectionRail's result too, because they are literally the same object in
    memory. Audit logs would show data from checks that never happened, and the
    bug only surfaces once two instances exist — so a single-object test passes
    happily while production rots.

    `default_factory` takes a *callable* instead of a value. The dataclass
    machinery calls `dict()` fresh for each new instance, so every RailResult
    gets its own dict.

    Python's dataclass module actually knows this trap is dangerous and refuses
    the inline form: writing `metadata: dict = {}` raises ValueError at class
    definition time. Try it once, read the error, and you will never forget it.
    """


@dataclass
class PipelineResult:
    """The outcome of running a whole ordered list of rails over one input.

    Distinct from RailResult because callers ask a different question of it. A
    RailResult answers "what did *this* rail think?"; a PipelineResult answers
    "may I send this text to the model, and if not, who stopped it?".

    Populated per the aggregation rule in the Week-1 spec:
      - working_text starts as the input
      - each rail's result is appended to `results` regardless of verdict
      - BLOCK    -> stop immediately; blocked=True, final_text=None, blocking=r
      - TRANSFORM-> working_text = r.text; keep going
      - ALLOW    -> keep going
      - all pass -> blocked=False, final_text=working_text, blocking=None
    """

    blocked: bool
    """True if any rail returned BLOCK. The one field most callers check."""

    final_text: str | None
    """Text to actually send onward, after any TRANSFORM rewrites were applied.

    None when blocked — deliberately. If a blocked pipeline still handed back a
    string, a caller who forgot to check `blocked` would happily forward hostile
    input to the model. None makes that mistake crash loudly instead of leaking.
    """

    blocking: "RailResult | None"
    """The single result that caused the block, or None if nothing blocked.

    A convenience: it is always the last entry of `results` when blocked=True,
    but pulling it out means error handling and log lines do not have to index
    into a list and reason about whether it is empty.
    """

    results: list[RailResult] = field(default_factory=list)
    """Every rail result collected, in execution order, including ALLOWs.

    The full trace, for the audit log and the red-team report — you want to know
    which rails ran and passed before one blocked, not only the one that fired.

    Same `default_factory` reasoning as `RailResult.metadata`: a list is mutable,
    so an inline `= []` default would be shared across every PipelineResult and
    accumulate results from unrelated runs forever.
    """
