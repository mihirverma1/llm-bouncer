"""Rails: the individual checks a pipeline runs, in order.

Each rail inspects a piece of text and returns a `RailResult` saying ALLOW,
BLOCK, or TRANSFORM. Rails know nothing about each other and nothing about the
pipeline — that isolation is what makes them individually testable and lets
users add their own without touching library code.

The contract every rail satisfies lives in `base.py`.
"""

from llm_bouncer.rails.base import Rail

__all__ = ["Rail"]
