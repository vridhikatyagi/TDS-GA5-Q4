from typing import List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from scanner import audit_skill

app = FastAPI(title="Skill Safety Audit Scanner API")

class ScanRequest(BaseModel):
    skill: str

class ScanResponse(BaseModel):
    categories: List[str]

@app.post("/", response_model=ScanResponse)
@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(payload: ScanRequest):
    if not payload.skill:
        raise HTTPException(status_code=400, detail="Skill payload cannot be empty.")
    
    flagged_categories = audit_skill(payload.skill)
    return {"categories": flagged_categories}
