from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from parser.evtx_parser import parse_evtx
import tempfile
import os

app = FastAPI(title="SIGIL EVTX Parser Backend", version="1.0.0")

# CORS — allow SIGIL frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "sigil-evtx-parser"}


@app.post("/upload-evtx/")
async def upload_evtx(file: UploadFile = File(...)):
    try:
        # Save temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        # Parse EVTX
        events = parse_evtx(tmp_path)

        os.remove(tmp_path)

        return {
            "status": "success",
            "filename": file.filename,
            "event_count": len(events),
            "events": events[:5000]  # increased limit for thorough analysis
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}