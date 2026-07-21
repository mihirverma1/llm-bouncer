"""LengthRail — caps how much text a caller may send.

The simplest possible rail, and deliberately the first one built: it proves the
whole `Rail` -> `RailResult` -> `Pipeline` contract end to end with logic nobody
can argue about. If this rail works, the plumbing works, and every later rail is
just a smarter `check` body.

It is not a toy, though. An unbounded input field is a real problem:

  - **Cost.** Tokens are billed. A user pasting a 5 MB log file into a chat box
    is an expensive accident, and a script doing it in a loop is an expensive
    attack.
  - **Context flooding.** Oversized input can push your system prompt out of the
    model's context window entirely — the instructions that hold your guardrails
    in place get evicted by sheer volume. That makes a length cap a genuine
    injection defence, not merely a cost control.
  - **Denial of service.** Long inputs are slow to embed, slow to retrieve
    against, and slow to generate from.

Rate limiting (N requests per time window) also belongs to this rail per the
spec, but arrives in a later task. This file handles size only.
"""

from llm_bouncer.rails.base import Rail
from llm_bouncer.result import RailResult, Severity


class LengthRail(Rail):
    """Blocks text longer than `max_len` characters.

    Example::

        rail = LengthRail(max_len=4000)
        rail.check("hello")               # ALLOW
        rail.check("x" * 5000)            # BLOCK

    Args:
        max_len: Maximum allowed length, in characters. Must be positive.

    Raises:
        ValueError: If `max_len` is not a positive integer.
    """

    name = "length"

    def __init__(self, max_len: int) -> None:
        # Validate in the constructor, not in check().
        #
        # This is the one place a rail *should* raise. The rule "never raise on
        # hostile input" is about the text being checked — a bad string is the
        # normal case and returns BLOCK. But `max_len=0` is not hostile input, it
        # is a programmer misconfiguring the rail, and it would silently block
        # every single request. Failing loudly at construction surfaces that at
        # startup rather than as a mystery outage.
        #
        # `isinstance(max_len, bool)` is checked explicitly because in Python
        # `bool` subclasses `int`, so `LengthRail(max_len=True)` would otherwise
        # sail through as a limit of 1 character.
        if isinstance(max_len, bool) or not isinstance(max_len, int):
            raise ValueError(f"max_len must be an int, got {type(max_len).__name__}")
        if max_len <= 0:
            raise ValueError(f"max_len must be positive, got {max_len}")

        self.max_len = max_len

    def check(self, text: str) -> RailResult:
        """BLOCK if `text` is longer than `max_len`, otherwise ALLOW.

        Boundary rule: the comparison is `>`, so a string of exactly `max_len`
        characters is ALLOWED. `max_len` reads as "the maximum permitted length",
        and a maximum you are not allowed to reach would be a surprising thing to
        call a maximum. The alternative (`>=`) would mean `max_len=4000` really
        permits 3999, which is the kind of off-by-one that quietly turns into a
        support ticket.

        The boundary is not a matter of taste — it is tested explicitly in
        `tests/test_length.py`, so the choice is pinned rather than implied.
        """
        length = len(text)

        if length > self.max_len:
            return self._block(
                # Concrete numbers, not "input too long". This string lands in
                # the audit log and in the red-team report, where the first
                # question anyone asks is "by how much?".
                f"length {length} > max {self.max_len}",
                # LOW because an oversized input is usually a clumsy user, not an
                # attacker. Severity does not affect control flow — the pipeline
                # stops on any BLOCK — it only ranks the finding, and treating
                # every paste of a big document as CRITICAL would bury the real
                # injection attempts underneath.
                severity=Severity.LOW,
                length=length,
                max_len=self.max_len,
            )

        # Metadata on the ALLOW path too. Slightly unusual, but the audit log
        # becomes much more useful for tuning: seeing that real traffic peaks at
        # 900 characters tells you a 4000 cap is comfortable, which you cannot
        # learn from blocked requests alone.
        return self._allow(length=length, max_len=self.max_len)
