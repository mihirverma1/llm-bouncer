"""The `Rail` contract — what every check in the library must look like.

One method, one return type:

    rail.check(text) -> RailResult

That is the entire interface. `LengthRail`, `InjectionRail`, and `SecretsRail`
all implement it; the `Pipeline` calls it without knowing or caring which rail
it is holding. Adding a fourth rail requires changing nothing else.

Design source: docs/superpowers/specs/2026-07-20-llm-bouncer-week1-design.md
and docs/decisions/ADR-001-api-shape.md.

--------------------------------------------------------------------------
Why an abstract base class rather than a typing.Protocol
--------------------------------------------------------------------------
Both options were on the table, and they answer different questions.

A `Protocol` is *structural typing*: any object with a matching `check` method
counts as a Rail, with no import and no inheritance. Maximum freedom for third
parties, but it can only describe a shape — it cannot carry code.

An abstract base class is *nominal typing*: you inherit from it. That costs an
import, but it can ship shared behaviour, and here there is real behaviour worth
sharing. Every rail otherwise repeats the same construction:

    return RailResult(Verdict.BLOCK, "length", reason=..., severity=..., metadata=...)

...with its own name spelled out by hand each time, which is exactly the kind of
string that gets copy-pasted wrong. The `_allow` / `_block` / `_transform`
helpers below fill in `self.name` automatically, so a rail body reads as intent
rather than as boilerplate.

The freedom argument mostly evaporates on inspection: `Pipeline` calls
`rail.check(text)` by duck typing and never runs an `isinstance` check. So a
third party who dislikes the base class can still pass any object with a
matching `check` method and it will work. The ABC is a convenience, not a gate.

Decision: abstract base class, with duck typing left deliberately intact.
Recorded in ADR-001.
"""

from abc import ABC, abstractmethod

from llm_bouncer.result import RailResult, Severity, Verdict


class Rail(ABC):
    """Base class for every guardrail check.

    Subclasses must do two things:

      1. Set `name` — a short string identifying the rail in results and audit
         logs, e.g. "length", "injection", "secrets".
      2. Implement `check(text)`.

    Minimal example::

        class ShoutRail(Rail):
            name = "shout"

            def check(self, text: str) -> RailResult:
                if text.isupper():
                    return self._block("all caps", severity=Severity.LOW)
                return self._allow()

    Note `name` is a plain class attribute rather than an enum member, so a user
    can add a rail without patching anything in the library.
    """

    name: str = "rail"
    """Short identifier, overridden by every subclass.

    The fallback value exists only so a subclass that forgets to set one still
    produces a result rather than an AttributeError. A forgotten name shows up as
    a suspicious "rail" in the audit log, which is the intended nudge.
    """

    @abstractmethod
    def check(self, text: str) -> RailResult:
        """Inspect `text` and return a verdict.

        This is the one method a rail must implement. Rules it must follow:

        - **Never raise for hostile input.** A malformed or adversarial string is
          the normal case, not an error — return BLOCK. An exception escaping a
          rail takes down the whole pipeline, which fails *open* if the caller
          catches broadly. Reserve exceptions for genuine programmer error, such
          as a bad constructor argument.
        - **Never mutate `text`.** Return the rewrite in `RailResult.text` with a
          TRANSFORM verdict, and let the pipeline decide to adopt it. A rail that
          edits in place makes execution order impossible to reason about.
        - **Be deterministic.** Same input, same verdict. The Week-3 red-team
          harness replays payloads and diffs the results; a rail that sometimes
          decides differently makes that report meaningless.

        Marked `@abstractmethod`, so Python refuses to instantiate any subclass
        that has not implemented it — the failure lands at construction time with
        a clear message, instead of as an AttributeError deep inside a pipeline
        run.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Result builders
    #
    # Convenience only — a subclass is free to construct RailResult directly.
    # They exist because every rail would otherwise hand-write `self.name` into
    # every result, and a mistyped name silently corrupts the audit trail
    # without failing any test.
    # ------------------------------------------------------------------

    def _allow(self, reason: str = "", **metadata) -> RailResult:
        """Build an ALLOW result: text is clean, continue to the next rail.

        `reason` defaults to empty because a passing check usually has nothing
        interesting to say, and a log full of "looked fine" lines is noise.

        Severity is deliberately not a parameter: an ALLOW is by definition not
        a finding, so it stays LOW.
        """
        return RailResult(
            Verdict.ALLOW,
            self.name,
            reason=reason,
            metadata=metadata,
        )

    def _block(
        self,
        reason: str,
        severity: Severity = Severity.LOW,
        **metadata,
    ) -> RailResult:
        """Build a BLOCK result: stop the pipeline here.

        `reason` is required, unlike in `_allow`. A block is the one outcome a
        human will have to explain to a confused user or investigate in a log,
        so it must always carry a sentence. Make it factual and specific —
        "length 5210 > max 4000" beats "input rejected".

        `severity` defaults to LOW so a rail must consciously opt in to raising
        the alarm. It does not affect control flow — the pipeline stops on any
        BLOCK — it only ranks the finding for triage and reporting.
        """
        return RailResult(
            Verdict.BLOCK,
            self.name,
            reason=reason,
            severity=severity,
            metadata=metadata,
        )

    def _transform(
        self,
        text: str,
        reason: str,
        severity: Severity = Severity.LOW,
        **metadata,
    ) -> RailResult:
        """Build a TRANSFORM result: text was rewritten, continue with the new one.

        `text` is the *replacement* — the full rewritten string, not a diff or a
        fragment. The pipeline assigns it directly to its working text, and every
        later rail sees only the rewritten version.

        Used by redacting rails: `SecretsRail` finding an API key returns the
        prompt with the key swapped for a placeholder, so the user's actual
        question still reaches the model while the secret does not.
        """
        return RailResult(
            Verdict.TRANSFORM,
            self.name,
            reason=reason,
            severity=severity,
            text=text,
            metadata=metadata,
        )

    def __repr__(self) -> str:
        """Readable in a pipeline dump and in pytest failure output.

        `Pipeline([LengthRail(max_len=4000), InjectionRail()])` printing as a row
        of `<object at 0x...>` makes a failing test needlessly hard to read.
        """
        return f"<{type(self).__name__} name={self.name!r}>"
