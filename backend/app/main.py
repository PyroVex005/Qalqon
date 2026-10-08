from urllib.parse import urlparse
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import ThreatHash, DomainReputation, PackageReputation, CertificateReputation, ThreatReport
from .schemas import *

app = FastAPI(title="QALQON Reputation API", version="1.0.0")

@app.on_event("startup")
def startup(): Base.metadata.create_all(engine)

@app.get("/api/v1/health")
def health(): return {"status":"ok"}

def response(row):
    if not row: return ReputationResponse(status="unknown", confidence=0.0, source=None)
    return ReputationResponse(status=row.classification, confidence=row.confidence, source=row.source)

@app.post("/api/v1/reputation/hash", response_model=ReputationResponse)
def hash_rep(req: HashRequest, db: Session=Depends(get_db)):
    return response(db.query(ThreatHash).filter(ThreatHash.sha256 == req.sha256.lower()).first() or db.query(ThreatHash).filter(ThreatHash.sha256 == req.sha256.upper()).first())

@app.post("/api/v1/reputation/url", response_model=ReputationResponse)
def url_rep(req: UrlRequest, db: Session=Depends(get_db)):
    host = (urlparse(req.url).hostname or "").lower().strip('.')
    if not host: return ReputationResponse(status="unknown")
    row = db.query(DomainReputation).filter(DomainReputation.domain == host).first()
    return response(row)

@app.post("/api/v1/reputation/package", response_model=ReputationResponse)
def package_rep(req: PackageRequest, db: Session=Depends(get_db)):
    return response(db.query(PackageReputation).filter(PackageReputation.package_name == req.package_name).first())

@app.post("/api/v1/reputation/certificate", response_model=ReputationResponse)
def certificate_rep(req: CertificateRequest, db: Session=Depends(get_db)):
    return response(db.query(CertificateReputation).filter(CertificateReputation.fingerprint_sha256 == req.fingerprint_sha256.upper()).first())

@app.post("/api/v1/report")
def report(req: ReportRequest, db: Session=Depends(get_db)):
    row = ThreatReport(indicator_type=req.indicator_type, indicator=req.indicator, reason=req.reason, status="SUBMITTED")
    db.add(row); db.commit(); db.refresh(row)
    return {"id":row.id,"status":row.status}

@app.get("/api/v1/threat-db/version")
def db_version(): return {"version": 1, "note": "No fabricated seed threats are included."}

@app.get("/api/v1/threat-db/delta")
def db_delta(): return {"version": 1, "hashes": [], "domains": []}
