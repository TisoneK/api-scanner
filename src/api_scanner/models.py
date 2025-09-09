"""
Data models for the API Scanner.
"""
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field

class RequestData(BaseModel):
    """Model representing an HTTP request."""
    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, List[str]] = Field(default_factory=dict)
    body: Optional[Union[Dict, List, str]] = None
    timestamp: str

class ResponseData(BaseModel):
    """Model representing an HTTP response."""
    status_code: int
    reason: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Union[Dict, List, str]] = None
    response_time_ms: float
    timestamp: str

class ApiCall(BaseModel):
    """Model representing a complete API call with request and response."""
    id: str
    request: RequestData
    response: ResponseData
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

    def dict(self, *args, **kwargs):
        """Override dict method to handle custom JSON encoding."""
        data = super().dict(*args, **kwargs)
        # Ensure all datetime objects are properly serialized
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data
