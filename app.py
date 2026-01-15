import os
import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
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
from modules.bug_bounty_dorks import get_bug_bounty_dorks, get_dork_categories
from modules.osint_explorer import OSINTExplorer

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
            except Exception:
                pass

manager = ConnectionManager()

app = FastAPI(title="Google Dorking & exposure Detection Tool")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Load Config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Ensure reports directory exists
os.makedirs("reports", exist_ok=True)

# Mount static files for reports
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

@app.get("/", response_class=HTMLResponse)
async def read_index():
    return FileResponse("frontend/index.html")

@app.get("/download/{filename}")
async def download_report(filename: str):
    file_path = os.path.join("reports", filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    raise HTTPException(status_code=404, detail="File not found")

@app.post("/scan")
async def start_scan(
    manual_urls: Optional[str] = Form(None),
    dork_file: Optional[UploadFile] = File(None),
    authorized: bool = Form(...)
):
    if not authorized:
        raise HTTPException(status_code=400, detail="You must be authorized to scan the targets.")

    urls = []
    
    # Check for manual URLs
    if manual_urls:
        urls = [u.strip() for u in manual_urls.split(",") if u.strip()]
        await manager.broadcast({"type": "log", "message": f"Added {len(urls)} manual URLs."})

    # Load dorks if file provided
    if dork_file:
        content = await dork_file.read()
        dorks_path = "dorks/uploaded_dorks.txt"
        with open(dorks_path, "wb") as f:
            f.write(content)
        
        dorks = load_dorks(dorks_path)
        await manager.broadcast({"type": "log", "message": f"Loaded {len(dorks)} dorks from file."})
        for i, dork in enumerate(dorks, 1):
            await manager.broadcast({"type": "log", "message": f"Running dork {i}/{len(dorks)}: {dork}"})
            # Perform search per dork
            found_urls = google_search(dork, num_results=config["google_search"]["max_results_per_dork"])
            urls.extend(found_urls)
            if found_urls:
                await manager.broadcast({"type": "log", "message": f"Found {len(found_urls)} URLs for dork: {dork}"})

    if not urls:
        await manager.broadcast({"type": "log", "message": "No URLs found to scan."})
        return {"message": "No URLs found to scan.", "results": []}

    # Scrape and Analyze
    scraper = SeleniumScraper(
        headless=config["scraper"]["headless"],
        timeout=config["scraper"]["timeout"],
        rate_limit_delay=config["scraper"]["rate_limit_delay"]
    )
    analyzer = AIAnalyzer()
    
    scan_results = []
    unique_urls = list(set(urls))
    await manager.broadcast({"type": "log", "message": f"Starting scan on {len(unique_urls)} unique URLs."})
    
    for i, url in enumerate(unique_urls, 1):
        await manager.broadcast({"type": "log", "message": f"Scraping {i}/{len(unique_urls)}: {url}"})
        content = scraper.fetch_content(url)
        if content:
            await manager.broadcast({"type": "log", "message": f"Analyzing content for: {url}"})
            findings = analyzer.analyze(content)
            score, level = calculate_risk_score(findings, config)
            
            result = {
                "url": url,
                "findings": findings,
                "risk_score": score,
                "risk_level": level
            }
            scan_results.append(result)
            # Broadcast the individual result
            await manager.broadcast({"type": "result", "data": result})
            if score > 0:
                 await manager.broadcast({"type": "log", "message": f"⚠️ Found {len(findings)} exposures on {url} (Risk: {level})"})
    
    scraper.close()
    await manager.broadcast({"type": "log", "message": "Scan complete. Generating reports..."})

    # Generate Reports
    json_report, csv_report = generate_reports(scan_results, "reports")
    await manager.broadcast({"type": "log", "message": f"Reports saved to reports folder."})

    return {
        "message": "Scan complete",
        "results": scan_results,
        "reports": {
            "json": json_report,
            "csv": csv_report
        }
    }

@app.post("/bug-bounty-scan")
async def bug_bounty_scan(
    target_domain: str = Form(...),
    authorized: bool = Form(...)
):
    """
    Bug Bounty Hunter Auto-Scan Mode
    Automatically generates and runs 100+ Google dorks for the target domain
    """
    if not authorized:
        raise HTTPException(status_code=400, detail="You must be authorized to scan the targets.")
    
    # Clean domain input
    target_domain = target_domain.strip().replace('http://', '').replace('https://', '').replace('www.', '')
    
    await manager.broadcast({"type": "log", "message": f"[*] Starting Bug Bounty Auto-Scan for: {target_domain}"})
    
    # OSINT / Shodan Scan
    osint_results = {}
    if config.get("osint", {}).get("shodan_enabled"):
        await manager.broadcast({"type": "log", "message": f"[*] Fetching Network Footprint from Shodan for {target_domain}..."})
        explorer = OSINTExplorer()
        osint_results = explorer.scan_domain(target_domain)
        if osint_results.get("enabled"):
            await manager.broadcast({"type": "osint", "data": osint_results})
            await manager.broadcast({"type": "log", "message": f"[*] Shodan found {len(osint_results.get('ports', []))} open ports."})
    
    # Generate comprehensive dork list
    dorks = get_bug_bounty_dorks(target_domain)
    await manager.broadcast({"type": "log", "message": f"[*] Generated {len(dorks)} automated dorks for {target_domain}"})
    
    # Execute search for each dork
    urls = []
    for i, dork in enumerate(dorks, 1):
        if i % 5 == 0 or i == 1: # Broadcast every 5 dorks to avoid flooding
            await manager.broadcast({"type": "log", "message": f"[*] Running dork {i}/{len(dorks)}: {dork}"})
        found_urls = google_search(dork, num_results=config["google_search"]["max_results_per_dork"])
        if found_urls:
            await manager.broadcast({"type": "log", "message": f"Found {len(found_urls)} URLs for dork: {dork}"})
            urls.extend(found_urls)
    
    if not urls:
        await manager.broadcast({"type": "log", "message": f"No results found for {target_domain}."})
        return {
            "message": f"No results found for {target_domain}. Make sure Google API credentials are configured.",
            "results": [],
            "stats": {
                "total_dorks": len(dorks),
                "urls_found": 0
            }
        }
    
    # Remove duplicates
    urls = list(set(urls))
    await manager.broadcast({"type": "log", "message": f"[*] Found {len(urls)} unique URLs to scan"})
    
    # Scrape and Analyze
    scraper = SeleniumScraper(
        headless=config["scraper"]["headless"],
        timeout=config["scraper"]["timeout"],
        rate_limit_delay=config["scraper"]["rate_limit_delay"]
    )
    analyzer = AIAnalyzer()
    
    scan_results = []
    
    for i, url in enumerate(urls, 1):
        await manager.broadcast({"type": "log", "message": f"[*] Scanning URL {i}/{len(urls)}: {url}"})
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
            # Broadcast the individual result
            await manager.broadcast({"type": "result", "data": result})
            if score > 0:
                 await manager.broadcast({"type": "log", "message": f"⚠️ Found {len(findings)} exposures on {url} (Risk: {level})"})
    
    scraper.close()
    await manager.broadcast({"type": "log", "message": f"Bug Bounty scan complete for {target_domain}. Generating reports..."})
    
    # Generate Reports
    json_report, csv_report = generate_reports(scan_results, "reports")
    await manager.broadcast({"type": "log", "message": f"Reports saved to reports folder."})
    
    return {
        "message": f"Bug Bounty scan complete for {target_domain}",
        "results": scan_results,
        "osint": osint_results,
        "reports": {
            "json": json_report,
            "csv": csv_report
        },
        "stats": {
            "total_dorks": len(dorks),
            "urls_found": len(urls),
            "urls_scanned": len(scan_results),
            "high_risk": len([r for r in scan_results if r["risk_level"] == "HIGH"]),
            "medium_risk": len([r for r in scan_results if r["risk_level"] == "MEDIUM"]),
            "low_risk": len([r for r in scan_results if r["risk_level"] == "LOW"])
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
