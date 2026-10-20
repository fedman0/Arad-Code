from __future__ import annotations
from contextvars import ContextVar
from dataclasses import asdict, dataclass, fields
from typing import Callable, Optional

usage_scope: ContextVar[str] = ContextVar("arad_usage_scope", default="")


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    cached_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    cost: float = 0.0
    unpriced_calls: int = 0
    seconds: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def cost_known(self) -> bool:
        return self.unpriced_calls == 0

    def add(self, other: "Usage") -> None:
        for f in fields(self):
            setattr(self, f.name, getattr(self, f.name) + getattr(other, f.name))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["total_tokens"] = self.total_tokens
        d["cost_known"] = self.cost_known
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Usage":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in names})


def _price(pricing: dict, model: str) -> Optional[dict]:
    if not pricing:
        return None
    entry = pricing.get(model)
    if entry is None and "/" in model:
        entry = pricing.get(model.split("/", 1)[1])
    if not isinstance(entry, dict):
        return None
    try:
        price = {"input": float(entry["input"]), "output": float(entry["output"])}
    except (KeyError, TypeError, ValueError):
        return None
    try:
        price["cached_input"] = float(entry.get("cached_input", price["input"]))
    except (TypeError, ValueError):
        price["cached_input"] = price["input"]
    return price


def cost_for(pricing: dict, model: str, prompt: int, cached: int, completion: int) -> Optional[float]:
    price = _price(pricing, model)
    if price is None:
        return None
    cached = max(0, min(cached, prompt))
    return ((prompt - cached) * price["input"] + cached * price["cached_input"]
            + completion * price["output"]) / 1_000_000


def has_price(pricing: dict, model: str) -> bool:
    return _price(pricing, model) is not None


def format_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


def format_cost(u: Usage) -> str:
    if u.calls and not u.cost_known and u.cost == 0:
        return "?"
    text = f"${u.cost:.2f}" if u.cost >= 0.01 or u.cost == 0 else f"${u.cost:.4f}"
    return text if u.cost_known else text + "+?"


class UsageMeter:
    def __init__(self, pricing: Optional[dict] = None, budget_usd: Optional[float] = None,
                 token_budget: Optional[int] = None):
        self.pricing = pricing or {}
        self.budget_usd = budget_usd
        self.token_budget = token_budget
        self.total = Usage()
        self._by_key: dict[tuple[str, str], Usage] = {}
        self._listeners: list[Callable[[str, str, Usage], None]] = []

    def on_record(self, listener: Callable[[str, str, Usage], None]) -> None:
        self._listeners.append(listener)

    def check(self) -> None:
        if self.budget_usd is not None and self.total.cost >= self.budget_usd:
            raise BudgetExceeded(
                f"budget reached: spent ${self.total.cost:.2f} of ${self.budget_usd:.2f}")
        if self.token_budget is not None and self.total.total_tokens >= self.token_budget:
            raise BudgetExceeded(
                f"token budget reached: used {self.total.total_tokens:,} of {self.token_budget:,} tokens")

    def record(self, model: str, prompt_tokens: int = 0, completion_tokens: int = 0,
               cached_tokens: int = 0, reasoning_tokens: int = 0, seconds: float = 0.0,
               provider_cost: Optional[float] = None, measured: bool = True) -> Usage:
        cost = provider_cost
        if cost is None and measured:
            cost = cost_for(self.pricing, model, prompt_tokens, cached_tokens, completion_tokens)
        u = Usage(calls=1, prompt_tokens=prompt_tokens, cached_tokens=cached_tokens,
                  completion_tokens=completion_tokens, reasoning_tokens=reasoning_tokens,
                  cost=cost or 0.0, unpriced_calls=0 if cost is not None else 1, seconds=seconds)
        scope = usage_scope.get()
        self.total.add(u)
        self._by_key.setdefault((scope, model), Usage()).add(u)
        for listener in list(self._listeners):
            try:
                listener(scope, model, u)
            except Exception:
                pass
        return u

    def for_scope(self, scope: str) -> dict[str, Usage]:
        return {m: u for (s, m), u in self._by_key.items() if s == scope}

    def rows(self) -> list[tuple[str, str, Usage]]:
        return [(s, m, u) for (s, m), u in self._by_key.items()]
