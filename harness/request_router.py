from __future__ import annotations

from .capability_registry import CAPABILITIES
from .models import RouterMatch


class EmailAgentRouter:
    def route(self, prompt: str, limit: int = 5) -> list[RouterMatch]:
        tokens = {
            token.lower()
            for token in prompt.replace("/", " ").replace("-", " ").replace("_", " ").split()
            if token
        }
        matches: list[RouterMatch] = []
        for capability in CAPABILITIES:
            score = 0
            matched_terms: list[str] = []
            haystacks = (
                capability.name.lower(),
                capability.responsibility.lower(),
                capability.source_hint.lower(),
            )
            for term in capability.trigger_terms:
                normalized = term.lower()
                if normalized in prompt.lower():
                    score += max(2, len(normalized.split()))
                    matched_terms.append(term)
            for token in tokens:
                if any(token in haystack for haystack in haystacks):
                    score += 1
                    matched_terms.append(token)
            if score > 0:
                matches.append(
                    RouterMatch(
                        name=capability.name,
                        kind=capability.kind,
                        score=score,
                        reason=", ".join(dict.fromkeys(matched_terms)) or capability.responsibility,
                    )
                )
        matches.sort(key=lambda item: (-item.score, item.kind, item.name))
        return matches[:limit]

