"""A tiny Prometheus-format metrics registry — stdlib only, house style.

The gateway hand-rolls its audit index, its bundle format, its JWKS cache; a
metrics client is the same call. `prometheus_client` is a fine library, but
`/metrics` is just a counter table rendered in a text format Prometheus scrapes,
and pulling a dependency into a security proxy to print integers is not the
trade this project makes (the golden rule: no heavy deps in the core install).
So this is ~100 lines that render the
[Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
and nothing more.

Two metric types cover everything the gateway needs: a **Counter** (monotonic —
tool calls, denials, redactions) and a **Gauge** (a level — live sessions, build
info). Both carry labels; a label set is a point. Increments are guarded by a
lock because they arrive from concurrent asyncio tasks (many sessions on one
central process), and a scrape reads a consistent snapshot.

Cardinality is a deliberate non-feature: labels here are always *bounded* sets
(an action name, an outcome, an event name), never a tool name or a principal id.
An unbounded label is how a metrics endpoint becomes the memory leak that takes
down the thing it was supposed to observe.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


def _format_labels(names: tuple[str, ...], values: tuple[str, ...]) -> str:
    if not names:
        return ""
    pairs = ",".join(f'{n}="{_escape(v)}"' for n, v in zip(names, values, strict=True))
    return "{" + pairs + "}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass(slots=True)
class _Metric:
    name: str
    help: str
    type: str                       # "counter" | "gauge"
    label_names: tuple[str, ...]
    _values: dict[tuple[str, ...], float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _key(self, labels: dict[str, str]) -> tuple[str, ...]:
        if set(labels) != set(self.label_names):
            raise ValueError(
                f"metric {self.name!r} expects labels {self.label_names}, got {tuple(labels)}"
            )
        return tuple(str(labels[n]) for n in self.label_names)

    def _add(self, amount: float, labels: dict[str, str]) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def _set(self, value: float, labels: dict[str, str]) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = value

    def samples(self) -> list[tuple[tuple[str, ...], float]]:
        with self._lock:
            return sorted(self._values.items())


class Counter:
    """A monotonically increasing value (resets only on process restart)."""

    def __init__(self, metric: _Metric):
        self._m = metric

    def inc(self, amount: float = 1.0, /, **labels: str) -> None:
        if amount < 0:
            raise ValueError("a counter cannot decrease")
        self._m._add(amount, labels)


class Gauge:
    """A value that can go up or down (a level, not a total)."""

    def __init__(self, metric: _Metric):
        self._m = metric

    def set(self, value: float, /, **labels: str) -> None:
        self._m._set(value, labels)

    def inc(self, amount: float = 1.0, /, **labels: str) -> None:
        self._m._add(amount, labels)

    def dec(self, amount: float = 1.0, /, **labels: str) -> None:
        self._m._add(-amount, labels)


class Registry:
    """Holds metrics and renders them in the Prometheus text format."""

    def __init__(self) -> None:
        self._metrics: dict[str, _Metric] = {}
        self._lock = threading.Lock()

    def _register(self, name: str, help_: str, type_: str, labels: tuple[str, ...]) -> _Metric:
        with self._lock:
            existing = self._metrics.get(name)
            if existing is not None:
                # Idempotent: re-declaring the same metric returns the same
                # instance, so importing a module twice doesn't double-register.
                if existing.type != type_ or existing.label_names != labels:
                    raise ValueError(f"metric {name!r} already registered with a different shape")
                return existing
            metric = _Metric(name=name, help=help_, type=type_, label_names=labels)
            self._metrics[name] = metric
            return metric

    def counter(self, name: str, help_: str, labels: list[str] | None = None) -> Counter:
        return Counter(self._register(name, help_, "counter", tuple(labels or ())))

    def gauge(self, name: str, help_: str, labels: list[str] | None = None) -> Gauge:
        return Gauge(self._register(name, help_, "gauge", tuple(labels or ())))

    def render(self) -> str:
        """The full exposition text: HELP + TYPE + samples for every metric."""
        with self._lock:
            metrics = list(self._metrics.values())
        lines: list[str] = []
        for metric in sorted(metrics, key=lambda m: m.name):
            lines.append(f"# HELP {metric.name} {metric.help}")
            lines.append(f"# TYPE {metric.name} {metric.type}")
            samples = metric.samples()
            if not samples and not metric.label_names:
                lines.append(f"{metric.name} 0")     # an unlabeled metric reads as 0
            for values, amount in samples:
                lines.append(f"{metric.name}{_format_labels(metric.label_names, values)} "
                             f"{_render_number(amount)}")
        return "\n".join(lines) + "\n"


def _render_number(value: float) -> str:
    # Emit whole numbers without a trailing .0 (Prometheus accepts both, but
    # `5` reads cleaner than `5.0` for counters).
    return str(int(value)) if value == int(value) else repr(value)


CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# The process-wide default registry. Metrics defined against it are exposed by
# whichever app mounts `/metrics`. A test builds its own Registry for isolation.
REGISTRY = Registry()
