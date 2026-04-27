from pydantic import BaseModel, Field
from typing import Dict, Optional


class IngestPayload(BaseModel):
    program: str = Field(default="local-lab")
    user_label: str = Field(default="unknown")
    method: str
    url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    source_tool: str = "burp"
    source_note: Optional[str] = None
    timestamp: Optional[str] = None
