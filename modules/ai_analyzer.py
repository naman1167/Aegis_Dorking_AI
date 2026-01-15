import re
import yaml
import os
from modules.nlp_analyzer import NLPAnalyzer
from modules.ml_threat_classifier import MLThreatClassifier
from modules.vision_analyzer import VisionAnalyzer

class AIAnalyzer:
    def __init__(self, config_path="config.yaml"):
        # Load configuration
        self.config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        
        self.ai_settings = self.config.get("ai_settings", {})
        self.use_ml = self.ai_settings.get("use_ml", False)
        self.use_nlp = self.ai_settings.get("use_nlp", False)
        self.use_vision = self.ai_settings.get("use_vision", False)
        
        # Specific patterns for detection (Fast regex baseline)
        self.patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "google_api_key": r'AIza[0-9A-Za-z-_]{35}',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "openai_key": r'sk-[a-zA-Z0-9]{48}',
            "private_key": r'-----BEGIN (?:RSA |EC |DSA | )PRIVATE KEY-----',
            "sql_dump": r'CREATE TABLE|INSERT INTO|DROP TABLE',
            "password_alike": r'(?:password|pwd|secret|auth_token)\s*[:=]\s*["\']?([a-zA-Z0-9_@#$%^&+=]{4,})["\']?',
            "env_exposure": r'(?:DB_PASSWORD|AWS_SECRET_ACCESS_KEY|STRIPE_KEY)\s*='
        }
        
        # Initialize AI/ML modules
        self.nlp_engine = NLPAnalyzer() if self.use_nlp else None
        self.ml_engine = MLThreatClassifier() if self.use_ml else None
        self.vision_engine = VisionAnalyzer() if self.use_vision else None

    def analyze(self, content):
        """
        Main entry point for analysis. Uses an ensemble approach if enabled.
        """
        text = content.get("text", "")
        screenshot = content.get("screenshot", "")
        
        if not text and not screenshot:
            return []
            
        # 1. Regex Baseline (Always run)
        findings = self._regex_analyze(text)
        
        # 2. NLP Analysis (Entity extraction & context)
        nlp_data = {}
        if self.nlp_engine and text:
            nlp_data = self.nlp_engine.analyze(content)
            # Add NLP findings to total findings
            for pattern in nlp_data.get("sensitive_patterns", []):
                findings.append({
                    "type": pattern["type"],
                    "match": pattern.get("organization", "N/A"),
                    "context": pattern["context"],
                    "source": "nlp",
                    "confidence": pattern.get("confidence", 0.5)
                })

        # 3. ML Threat Classification
        if self.ml_engine and text:
            # Classify overall content
            overall_classification = self.ml_engine.classify_threat(text)
            
            # Analyze context for each regex finding with ML
            for finding in findings:
                if finding.get("source") != "nlp":
                    context_analysis = self.ml_engine.analyze_context(text, finding)
                    finding["ml_verification"] = context_analysis
                    finding["severity"] = context_analysis.get("severity", "UNKNOWN")
                    finding["confidence"] = context_analysis.get("ml_confidence", 0.5)

        # 4. Visual Analysis
        if self.use_vision:
            vision_result = {}
            if screenshot:
                vision_result = self.vision_engine.analyze_screenshot(screenshot)
            else:
                vision_result = self.vision_engine.mock_analyze(text)
            
            if vision_result.get("is_sensitive"):
                findings.append({
                    "type": "visual_exposure",
                    "match": vision_result.get("classification"),
                    "context": vision_result.get("analysis", "Detected via visual pattern matching."),
                    "source": "vision",
                    "confidence": 0.8 if vision_result.get("enabled") else 0.4
                })

        return findings

    def _regex_analyze(self, text):
        """
        Performs classic regex-based pattern matching.
        """
        findings = []
        for key, pattern in self.patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Extract context (50 chars before and after)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace('\n', ' ').strip()
                
                findings.append({
                    "type": key,
                    "match": match.group(),
                    "context": f"...{context}...",
                    "source": "regex"
                })
        return findings
