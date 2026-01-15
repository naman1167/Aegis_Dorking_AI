import os
import base64
import requests
from typing import Dict, Any

class VisionAnalyzer:
    """
    AI Visual Auditor that analyzes screenshots to detect sensitive UI elements.
    Interfaces with OpenAI's GPT-4o-mini or similar vision models.
    """
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.enabled = self.api_key is not None
        
        # UI Elements we want to detect
        self.target_elements = [
            "admin dashboard",
            "login page with hardcoded credentials",
            "cctv camera feed",
            "database management interface (phpmyadmin/kibana/grafana)",
            "directory listing",
            "error page with stack trace",
            "exposed source code",
            "cloud storage bucket with files"
        ]

    def analyze_screenshot(self, base64_image: str) -> Dict[str, Any]:
        """
        Sends the screenshot to the Vision API for analysis.
        """
        if not self.enabled:
            return {"enabled": False, "message": "Vision API key missing (OPENAI_API_KEY)"}

        if not base64_image:
            return {"enabled": True, "error": "No image provided"}

        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }

            payload = {
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"Analyze this website screenshot for security exposures. Is it one of these: {', '.join(self.target_elements)}? Respond with 'TYPE: [type]' and a brief justification. If nothing sensitive is found, respond 'TYPE: benign'."
                            },
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ],
                "max_tokens": 150
            }

            response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            analysis_text = result['choices'][0]['message']['content']

            # Basic parsing
            classification = "benign"
            if "TYPE:" in analysis_text:
                classification = analysis_text.split("TYPE:")[1].split("\n")[0].strip().lower()

            return {
                "enabled": True,
                "classification": classification,
                "analysis": analysis_text,
                "is_sensitive": classification != "benign"
            }

        except Exception as e:
            return {"enabled": True, "error": str(e)}

    def mock_analyze(self, text_content: str) -> Dict[str, Any]:
        """
        Fall-back heuristic analysis based on text when Vision is disabled.
        """
        text_lower = text_content.lower()
        if "dashboard" in text_lower or "admin" in text_lower:
            return {"enabled": False, "classification": "potential admin dashboard (heuristic)", "is_sensitive": True}
        return {"enabled": False, "classification": "benign", "is_sensitive": False}
