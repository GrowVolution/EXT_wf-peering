from dataclasses import dataclass, field
from datetime import datetime, UTC

from .entries import parse_ts

CATEGORY_WEIGHTS = {
    "integrity": 35,
    "keys": 25,
    "reachability": 15,
    "history": 15,
    "diversity": 10
}
SEVERITY_CAPS = { "critical": 20, "high": 60 }
MIN_OBSERVERS = 2
OBSERVER_CAP = 70


@dataclass
class Signal:
    id: str
    category: str
    value: int | None
    weight: int = 10
    severity: str = "normal"
    source: str = "local"
    observed_at: str | None = None
    max_age: int | None = None
    cap: int | None = None
    detail: dict = field(default_factory=dict)

    def fresh(self, now: datetime) -> bool:
        if self.max_age is None or self.observed_at is None: return True
        try: observed = parse_ts(self.observed_at)
        except ValueError: return False
        return (now - observed).total_seconds() <= self.max_age

    def to_dict(self, now: datetime) -> dict:
        state = "missing" if self.value is None else ("fresh" if self.fresh(now) else "stale")
        return {
            "id": self.id,
            "category": self.category,
            "value": self.value,
            "weight": self.weight,
            "severity": self.severity,
            "source": self.source,
            "observed_at": self.observed_at,
            "max_age": self.max_age,
            "state": state,
            "detail": self.detail
        }


def _failed(signal: Signal) -> bool:
    return signal.value is not None and signal.value < 50


def compute(signals: list[Signal], independent_observers: int, now: datetime | None = None,
            min_observers: int = MIN_OBSERVERS) -> dict:
    now = now or datetime.now(UTC)
    present = [signal for signal in signals if signal.value is not None and signal.fresh(now)]
    stale = [signal for signal in signals if signal.value is not None and not signal.fresh(now)]
    missing = [signal for signal in signals if signal.value is None]

    categories = {}
    for name, weight in CATEGORY_WEIGHTS.items():
        members = [signal for signal in signals if signal.category == name]
        live = [signal for signal in present if signal.category == name]
        total = sum(signal.weight for signal in members)
        have = sum(signal.weight for signal in live)
        score = round(sum(signal.value * signal.weight for signal in live) / have) if have else None
        categories[name] = {
            "weight": weight,
            "score": score,
            "completeness": round(100 * have / total) if total else 0,
            "signals": len(members)
        }

    weighted = [(CATEGORY_WEIGHTS[name], data["score"]) for name, data in categories.items()
                if data["score"] is not None]
    base = sum(w * s for w, s in weighted) / sum(w for w, _ in weighted) if weighted else None

    caps = []
    for signal in present:
        if not _failed(signal): continue
        cap = signal.cap if signal.cap is not None else SEVERITY_CAPS.get(signal.severity)
        if cap is not None: caps.append({ "signal": signal.id, "cap": cap, "severity": signal.severity })
    if independent_observers < min_observers:
        caps.append({ "signal": "independent_observers", "cap": OBSERVER_CAP, "severity": "high" })

    score = None
    if base is not None:
        score = base
        for cap in caps: score = min(score, cap["cap"])
        score = max(0, min(100, round(score)))

    total_weight = sum(signal.weight for signal in signals)
    present_weight = sum(signal.weight for signal in present)
    stale_weight = sum(signal.weight for signal in stale)
    completeness = round(100 * present_weight / total_weight) if total_weight else 0

    if not present: basis = "none"
    elif completeness < 35: basis = "insufficient"
    elif total_weight and stale_weight * 4 > total_weight: basis = "stale"
    elif completeness < 70: basis = "partial"
    else: basis = "complete"

    status = "assessed" if basis in ("complete", "partial") and independent_observers >= 1 else "unclear"
    critical = any(_failed(signal) and signal.severity == "critical" for signal in present)
    high = any(_failed(signal) and signal.severity == "high" for signal in present)
    if status == "unclear": level = "unclear"
    elif critical: level = "critical"
    elif high or (score is not None and score < 70): level = "warning"
    else: level = "ok"

    return {
        "score": score,
        "level": level,
        "status": status,
        "basis": basis,
        "completeness": completeness,
        "independent_observers": independent_observers,
        "categories": categories,
        "caps": caps,
        "counts": { "present": len(present), "stale": len(stale), "missing": len(missing) },
        "signals": [signal.to_dict(now) for signal in signals],
        "computed_at": now.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "color": color(score) if score is not None else None
    }


def hue(score: int) -> int:
    return round(max(0, min(100, int(score))) * 1.2)


def color(score: int) -> dict:
    h = hue(score)
    return {
        "hue": h,
        "accent": f"hsl({h}, 75%, 26%)",
        "border": f"hsl({h}, 75%, 32%)",
        "surface": f"hsl({h}, 80%, 95%)",
        "text": f"hsl({h}, 90%, 20%)",
        "accent_dark": f"hsl({h}, 75%, 65%)",
        "surface_dark": f"hsl({h}, 45%, 13%)",
        "text_dark": f"hsl({h}, 85%, 78%)"
    }


def hsl_to_rgb(h: float, s: float, l: float) -> tuple[float, float, float]:
    s, l = s / 100, l / 100
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    if h < 60: r, g, b = c, x, 0
    elif h < 120: r, g, b = x, c, 0
    elif h < 180: r, g, b = 0, c, x
    elif h < 240: r, g, b = 0, x, c
    elif h < 300: r, g, b = x, 0, c
    else: r, g, b = c, 0, x
    return r + m, g + m, b + m


def luminance(rgb: tuple[float, float, float]) -> float:
    def channel(value):
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(value) for value in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: tuple[float, float, float], b: tuple[float, float, float]) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)
