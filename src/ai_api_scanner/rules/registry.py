"""Rule registry — loads and filters scan rules."""

from ..core.engine import Rule


# All registered rules: (id, name, function)
_ALL_RULES: list[tuple[str, str, Rule]] = []


def register(rule_id: str, rule_name: str):
    """Decorator to register a rule function."""
    def decorator(fn: Rule) -> Rule:
        _ALL_RULES.append((rule_id, rule_name, fn))
        return fn
    return decorator


def load_rules(selected: list[str] | None = None) -> list[tuple[str, str, Rule]]:
    """Return rules to run. Import rule modules to trigger registration first."""
    # Import all rule modules so @register fires
    from . import auth         # noqa: F401
    from . import rate_limit   # noqa: F401
    from . import tls          # noqa: F401
    from . import cors         # noqa: F401
    from . import info_leak    # noqa: F401
    from . import key_format   # noqa: F401
    from . import enumeration  # noqa: F401
    from . import http_methods # noqa: F401
    from . import stream       # noqa: F401
    from . import ssrf         # noqa: F401

    if selected is None:
        return list(_ALL_RULES)
    return [(rid, rname, rfn) for rid, rname, rfn in _ALL_RULES if rid in selected]
