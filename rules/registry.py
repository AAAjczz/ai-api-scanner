"""Rule registry — loads and filters scan rules."""

from core.engine import Rule


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
    import rules.auth       # noqa: F401
    import rules.rate_limit # noqa: F401
    import rules.tls        # noqa: F401
    import rules.cors       # noqa: F401
    import rules.info_leak  # noqa: F401
    import rules.key_format # noqa: F401

    if selected is None:
        return list(_ALL_RULES)
    return [(rid, rname, rfn) for rid, rname, rfn in _ALL_RULES if rid in selected]
