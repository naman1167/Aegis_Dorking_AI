import os
import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict
import json
import asyncio

from modules.dork_loader import load_dorks
from modules.google_search import google_search
from modules.selenium_scraper import SeleniumScraper
from modules.ai_analyzer import AIAnalyzer
from modules.risk_scoring import calculate_risk_score
from modules.report_builder import generate_reports
from modules.bug_bounty_dorks import get_bug_bounty_dorks
from modules.osint_explorer import OSINTExplorer

app = FastAPI(title="Aegis Dorking AI")

# Mount reports directory as static
if not os.path.exists("reports"):
    os.makedirs("reports")
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

# Load configuration
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# WebSocket Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                continue

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
async def read_index():
    return FileResponse("frontend/index.html")

@app.get("/download/{filename}")
async def download_report(filename: str):
    file_path = os.path.join("reports", filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    raise HTTPException(status_code=404, detail="File not found")

async def run_scan_task(urls: List[str]):
    scraper = SeleniumScraper(
        headless=config["scraper"]["headless"],
        timeout=config["scraper"]["timeout"],
        rate_limit_delay=config["scraper"]["rate_limit_delay"]
    )
    analyzer = AIAnalyzer()
    
    unique_urls = list(set(urls))
    scan_results = []
    
    for i, url in enumerate(unique_urls, 1):
        await manager.broadcast({"type": "log", "message": f"Scraping {i}/{len(unique_urls)}: {url}"})
        content = scraper.fetch_content(url)
        if content:
            findings = analyzer.analyze(content)
            score, level = calculate_risk_score(findings, config)
            result = {
                "url": url,
                "findings": findings,
                "risk_score": score,
                "risk_level": level
            }
            scan_results.append(result)
            await manager.broadcast({"type": "result", "data": result})
            if score > 0:
                 await manager.broadcast({"type": "log", "message": f"⚠️ Found {len(findings)} exposures on {url} (Risk: {level})"})
    
    scraper.close()
    await manager.broadcast({"type": "log", "message": "Scan complete. Generating reports..."})
    json_report, csv_report = generate_reports(scan_results, "reports")
    
    final_data = {
        "type": "final_results",
        "data": {
            "message": "Scan complete",
            "results": scan_results,
            "reports": {"json": json_report, "csv": csv_report}
        }
    }
    await manager.broadcast(final_data)

@app.post("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    manual_urls: Optional[str] = Form(None),
    dork_file: Optional[UploadFile] = File(None),
    authorized: bool = Form(...),
):
    if not authorized:
        raise HTTPException(status_code=400, detail="Not authorized")
    
    urls = []
    if manual_urls:
        urls.extend([u.strip() for u in manual_urls.split(",") if u.strip()])
    
    if dork_file:
        content = await dork_file.read()
        dorks = content.decode().splitlines()
        for dork in dorks:
            if dork.strip():
                urls.extend(google_search(dork.strip(), num_results=config["google_search"]["max_results_per_dork"]))
    
    if not urls:
        return {"message": "No URLs found", "status": "error"}

    background_tasks.add_task(run_scan_task, urls)
    return {"message": "Scan started in background", "status": "started"}

async def run_bug_bounty_task(target_domain: str):
    await manager.broadcast({"type": "log", "message": f"[*] Starting Bug Bounty Auto-Scan for: {target_domain}"})
    
    osint_results = {}
    if config.get("osint", {}).get("shodan_enabled"):
        explorer = OSINTExplorer()
        osint_results = explorer.scan_domain(target_domain)
        if osint_results.get("enabled"):
            await manager.broadcast({"type": "osint", "data": osint_results})
    
    dorks = get_bug_bounty_dorks(target_domain)
    await manager.broadcast({"type": "log", "message": f"[*] Generated {len(dorks)} automated dorks."})
    
    urls = []
    for dork in dorks:
        found_urls = google_search(dork, num_results=config["google_search"]["max_results_per_dork"])
        urls.extend(found_urls)
            
    urls = list(set(urls))
    await manager.broadcast({"type": "log", "message": f"[*] Found {len(urls)} unique URLs to scan"})
    
    scraper = SeleniumScraper(headless=config["scraper"]["headless"], timeout=config["scraper"]["timeout"], rate_limit_delay=config["scraper"]["rate_limit_delay"])
    analyzer = AIAnalyzer()
    scan_results = []
    
    for i, url in enumerate(urls, 1):
        await manager.broadcast({"type": "log", "message": f"[*] Scanning {i}/{len(urls)}: {url}"})
        content = scraper.fetch_content(url)
        if content:
            findings = analyzer.analyze(content)
            score, level = calculate_risk_score(findings, config)
            result = {"url": url, "findings": findings, "risk_score": score, "risk_level": level}
            scan_results.append(result)
            await manager.broadcast({"type": "result", "data": result})
    
    scraper.close()
    json_report, csv_report = generate_reports(scan_results, "reports")
    
    final_data = {
        "type": "final_results",
        "data": {
            "message": "Bug Bounty scan complete",
            "results": scan_results,
            "osint": osint_results,
            "reports": {"json": json_report, "csv": csv_report},
            "stats": {
                "total_dorks": len(dorks), "urls_found": len(urls),
                "high_risk": len([r for r in scan_results if r["risk_level"] == "HIGH"]),
                "medium_risk": len([r for r in scan_results if r["risk_level"] == "MEDIUM"]),
                "low_risk": len([r for r in scan_results if r["risk_level"] == "LOW"])
            }
        }
    }
    await manager.broadcast(final_data)

@app.post("/bug-bounty-scan")
async def bug_bounty_scan(
    background_tasks: BackgroundTasks,
    target_domain: str = Form(...),
    authorized: bool = Form(...)
):
    if not authorized:
        raise HTTPException(status_code=400, detail="Not authorized")
    
    target_domain = target_domain.strip().replace('http://', '').replace('https://', '').replace('www.', '')
    background_tasks.add_task(run_bug_bounty_task, target_domain)
    return {"message": "Bug Bounty scan started", "status": "started"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
