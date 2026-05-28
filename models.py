"""Data models for API Monitor."""
from pydantic import BaseModel
from typing import Optional

class MonitorCreate(BaseModel):
    url: str
    name: Optional[str] = None

class UserCreate(BaseModel):
    email: str
    plan: str = "free"
