import os
import io
import json
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from core.engine import AegisTraceEngine
from core.ephemeral_cache import memory_store
from reporting.dossier_generator import ForensicDossierGenerator
from web.gmail_connector import GmailInboxConnector
from intel.stix_exporter import STIX21Exporter
from intel.soar_playbook import SOCPlaybookGenerator
from ai.forensic_copilot import AIForensicCopilot

app = FastAPI(
    title="TRACEON - AI Email Forensic Platform",
    description="Ephemeral Zero-Retention Email Forensics & Reverse Routing Intelligence",
    version="1.0.0"
)

# Enable CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = AegisTraceEngine(allow_online_geo=True)
copilot = AIForensicCopilot()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def cache_analysis_ephemeral(analysis: dict):
    case_id = analysis["case_id"]
    headers = analysis["headers"]
    hashes = analysis["hashes"]
    threat = analysis["threat_summary"]
    flagged = threat["flagged_engines_count"]

    color_class = "emerald" if flagged == 0 else ("amber" if flagged == 1 else "rose")

    history_item = {
        "case_id": case_id,
        "subject": headers.get("subject", "(No Subject)"),
        "from": headers.get("from_raw", "Unknown"),
        "sha256": hashes.get("sha256", "N/A"),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "verdict": threat.get("threat_verdict", "UNKNOWN"),
        "color_class": color_class
    }
    memory_store.set(case_id, analysis, history_item)


FAVICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='#06B6D4' stroke='#0284C7' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/></svg>"""


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=FAVICON_SVG, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request):
    return templates.TemplateResponse(request=request, name="privacy.html")


@app.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request):
    return templates.TemplateResponse(request=request, name="terms.html")


@app.post("/api/analyze")
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None)
):
    content: bytes = b""
    if file and file.filename:
        content = await file.read()
    elif raw_text and raw_text.strip():
        content = raw_text.encode('utf-8', errors='replace')
    else:
        raise HTTPException(status_code=400, detail="Please upload a file or paste headers.")

    try:
        analysis = engine.analyze_email(content)
        cache_analysis_ephemeral(analysis)
        return JSONResponse(content={"status": "success", "data": analysis})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Forensic scan error: {str(e)}")


@app.get("/api/case/{case_id}")
async def get_case(case_id: str):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired or not found in RAM.")
    return JSONResponse(content={"status": "success", "data": analysis})


@app.delete("/api/case/{case_id}")
async def delete_case(case_id: str):
    purged = memory_store.purge(case_id)
    return JSONResponse(content={"status": "success", "purged": purged})


@app.get("/api/history")
async def get_history():
    records = memory_store.get_history()
    return JSONResponse(content={"status": "success", "stats": {"total": len(records)}, "records": records})


@app.get("/api/chat/greeting/{case_id}")
async def get_greeting(case_id: str):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired from RAM.")
    greeting = copilot.generate_initial_greeting(analysis)
    return JSONResponse(content={"status": "success", "greeting": greeting})


@app.post("/api/chat/message")
async def chat_message(
    case_id: str = Form(...),
    message: str = Form(...),
    history: Optional[str] = Form("[]")
):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired from RAM.")
    try:
        h = json.loads(history) if history else []
    except Exception:
        h = []
    reply = copilot.answer_query(analysis, message, h)
    return JSONResponse(content={"status": "success", "reply": reply})


@app.get("/api/report/pdf/{case_id}")
async def get_pdf(case_id: str):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired from RAM.")
    pdf_bytes = ForensicDossierGenerator.generate_pdf(analysis)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=TRACEON_Dossier_{case_id[:8].upper()}.pdf"}
    )


@app.get("/api/report/stix/{case_id}")
async def get_stix(case_id: str):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired from RAM.")
    bundle = STIX21Exporter.generate_bundle(analysis)
    return StreamingResponse(
        io.BytesIO(json.dumps(bundle, indent=2).encode('utf-8')),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=TRACEON_STIX_{case_id[:8].upper()}.json"}
    )


@app.get("/api/playbook/{case_id}")
async def get_playbook(case_id: str):
    analysis = memory_store.get(case_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Case expired from RAM.")
    return JSONResponse(content={"status": "success", "playbook": SOCPlaybookGenerator.generate_playbook(analysis)})


@app.get("/api/gmail/demo")
async def get_demo_inbox():
    return JSONResponse(content={"status": "success", "messages": GmailInboxConnector.get_demo_inbox()})


@app.post("/api/gmail/scan_message")
async def scan_demo_msg(msg_id: str = Form(...), is_demo: Optional[bool] = Form(True)):
    raw_bytes = GmailInboxConnector.get_demo_email_bytes(msg_id)
    analysis = engine.analyze_email(raw_bytes)
    cache_analysis_ephemeral(analysis)
    return JSONResponse(content={"status": "success", "data": analysis})


@app.get("/api/graph")
async def get_graph():
    return JSONResponse(content={"status": "success", "elements": engine.graph_correlator.export_cytoscape_elements()})


@app.get("/api/health")
async def health():
    return JSONResponse(content={"status": "online", "engine": "TRACEON v1.0", "zero_retention_ttl_mins": 10})
