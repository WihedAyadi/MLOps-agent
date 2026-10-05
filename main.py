from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pathlib import Path
from typing import List,Dict,Any
import os
import json
from agent.main import MLOpsVerification


app=FastAPI(title="MLOps Verification Agent", description="Agent to check to check MLOps compliance", version="1.0.0")
templates=Jinja2Templates(directory="templates")

class CheckRequest(BaseModel):
    directory_path: str
    checks: List[str]=["all"]
    use_ai: bool=False
    openrouter_api_key: str=None  # Optional API key for AI-powered checks


class CheckResult(BaseModel):
    status: str
    directory: str
    issues: List[Dict[str, Any]]
    recommendations: List[str]
    deployment_readiness: float  # 0-100 score
    ai_insights: List[str] = []  # AI-powered insights
    fix_plan: List[Dict[str, Any]] = []  # Step-by-step fix plan


@app.post("/check", response_model=CheckResult)
async def check_directory(request: CheckRequest):
    """Check a directory for MLOps deployment readiness"""

    # Validate directory exists
    print(request)
    print("PATH RECEIVED:", repr(request.directory_path))
    print("EXISTS:", os.path.exists(request.directory_path))
    print("IS DIRECTORY:", os.path.isdir(request.directory_path))

    if not os.path.exists(request.directory_path):
        raise HTTPException(status_code=404, detail=f"Directory not found: {request.directory_path}")

    # Initialize checker with AI capabilities
    checker = MLOpsVerification(
        directory_path=request.directory_path,
        use_ai=request.use_ai,
        openrouter_api_key=request.openrouter_api_key
    )

    # Run checks
    try:
        results = checker.run_checks(request.checks)
        return CheckResult(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Check failed: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request,"index.html", {"request": request})

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)