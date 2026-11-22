"""Pydantic models for the OpenAI-compatible chat completions API."""
from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
class ChatMessage(BaseModel):
    role: str
    content: str
class ChatCompletionRequest(BaseModel):
    model: str = "mock-llm"
    messages: list[ChatMessage] = Field(min_length=1)
    max_tokens: int | None = None
    temperature: float | None = None
    response_format: dict[str, Any] | None = None
class Choice(BaseModel):
    index: int
    message: dict[str, str]
    finish_reason: str = "stop"
class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[Choice]
    usage: Usage
