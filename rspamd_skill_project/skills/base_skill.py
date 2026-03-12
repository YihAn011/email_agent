from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Generic, Optional, TypeVar

from pydantic import BaseModel

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


class SkillError(BaseModel):
    type: str
    message: str
    retryable: bool = False
    details: Optional[Dict[str, Any]] = None


class SkillMeta(BaseModel):
    skill_name: str
    skill_version: str
    latency_ms: Optional[int] = None
    timestamp_utc: Optional[str] = None
    endpoint: Optional[str] = None
    service_version: Optional[str] = None


class SkillResult(BaseModel, Generic[OutputT]):
    ok: bool
    data: Optional[OutputT] = None
    error: Optional[SkillError] = None
    meta: SkillMeta


class BaseSkill(ABC, Generic[InputT, OutputT]):
    name: str = ""
    description: str = ""
    version: str = "0.1.0"

    @abstractmethod
    def run(self, payload: InputT) -> SkillResult[OutputT]:
        raise NotImplementedError
