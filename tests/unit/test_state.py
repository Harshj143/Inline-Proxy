"""Session store."""

from mcp_gateway.state import MemorySessionStore


def test_get_or_create_is_stable():
    store = MemorySessionStore()
    s1 = store.get_or_create("abc")
    s2 = store.get_or_create("abc")
    assert s1 is s2                      # same session for the same id
    assert s1.id == "abc"


def test_distinct_ids_are_isolated():
    store = MemorySessionStore()
    a = store.get_or_create("a")
    b = store.get_or_create("b")
    a.mark_tainted("web.fetch")
    a.risk_score = 40
    assert not b.tainted and b.risk_score == 0   # no cross-session leakage


def test_get_without_create():
    store = MemorySessionStore()
    assert store.get("missing") is None
    store.get_or_create("here")
    assert store.get("here") is not None
