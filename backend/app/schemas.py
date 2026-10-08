from pydantic import BaseModel, Field
class HashRequest(BaseModel): sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
class UrlRequest(BaseModel): url: str
class PackageRequest(BaseModel): package_name: str = Field(min_length=1,max_length=255)
class CertificateRequest(BaseModel): fingerprint_sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
class ReputationResponse(BaseModel):
    status: str
    confidence: float = 0.0
    source: str | None = None
class ReportRequest(BaseModel):
    indicator_type: str = Field(max_length=30)
    indicator: str = Field(max_length=2048)
    reason: str = Field(default="", max_length=4000)
