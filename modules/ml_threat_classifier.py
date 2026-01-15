try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

from typing import List, Dict, Any
import warnings
warnings.filterwarnings('ignore')

class MLThreatClassifier:
    """
    Machine Learning-based threat classifier using transformers for zero-shot classification.
    """
    
    def __init__(self):
        self.classifier = None
        self.threat_labels = [
            "credential leak",
            "api key exposure",
            "database configuration",
            "private key exposure",
            "authentication token",
            "sensitive file exposure",
            "sql injection vulnerability",
            "path traversal vulnerability",
            "benign content"
        ]
        
        if not TRANSFORMERS_AVAILABLE:
            print("[!] Transformers not installed. ML classification disabled.")
            return

        try:
            print("[*] Loading zero-shot classification model (using distilbart for speed)...")
            self.classifier = pipeline(
                "zero-shot-classification",
                model="valhalla/distilbart-mnli-12-1",
                device=-1  # CPU mode
            )
            print("[+] ML threat classifier loaded successfully")
        except Exception as e:
            print(f"[!] Failed to load ML classifier: {e}")
            self.classifier = None
    
    def classify_threat(self, text: str, max_length: int = 500) -> Dict[str, Any]:
        """
        Classify the type of security threat using zero-shot classification.
        """
        if not self.classifier:
            return {"enabled": False, "error": "Classifier not loaded"}
        
        # Truncate text for performance
        text_sample = text[:max_length]
        
        try:
            result = self.classifier(
                text_sample,
                candidate_labels=self.threat_labels,
                multi_label=True
            )
            
            # Format results
            classifications = []
            for label, score in zip(result['labels'], result['scores']):
                if score > 0.3:  # Only include if confidence > 30%
                    classifications.append({
                        "label": label,
                        "confidence": round(score, 3)
                    })
            
            return {
                "enabled": True,
                "classifications": classifications,
                "top_threat": result['labels'][0] if result['labels'] else "unknown",
                "top_confidence": round(result['scores'][0], 3) if result['scores'] else 0.0
            }
        except Exception as e:
            print(f"[!] Classification error: {e}")
            return {"enabled": True, "error": str(e)}
    
    def batch_classify(self, texts: List[str]) -> List[Dict[str, Any]]:
        """
        Classify multiple texts in batch for efficiency.
        """
        if not self.classifier:
            return [{"enabled": False} for _ in texts]
        
        results = []
        for text in texts:
            results.append(self.classify_threat(text))
        
        return results
    
    def get_severity_score(self, classification: Dict[str, Any]) -> str:
        """
        Convert classification to severity level (LOW/MEDIUM/HIGH).
        """
        if not classification.get("enabled"):
            return "UNKNOWN"
        
        top_threat = classification.get("top_threat", "")
        confidence = classification.get("top_confidence", 0.0)
        
        # High severity threats
        high_severity = [
            "private key exposure",
            "database configuration",
            "credential leak",
            "sql injection vulnerability"
        ]
        
        # Medium severity threats
        medium_severity = [
            "api key exposure",
            "authentication token",
            "sensitive file exposure"
        ]
        
        if top_threat in high_severity and confidence > 0.6:
            return "HIGH"
        elif top_threat in medium_severity and confidence > 0.5:
            return "MEDIUM"
        elif top_threat == "benign content":
            return "LOW"
        elif confidence > 0.4:
            return "MEDIUM"
        else:
            return "LOW"
    
    def analyze_context(self, text: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the context around a finding to determine if it's a real threat.
        """
        if not self.classifier:
            return {"context_analysis": "disabled"}
        
        # Extract context around the finding
        match_text = finding.get("match", "")
        context = finding.get("context", text[:500])
        
        classification = self.classify_threat(context)
        
        return {
            "original_finding": finding.get("type"),
            "ml_classification": classification.get("top_threat"),
            "ml_confidence": classification.get("top_confidence"),
            "severity": self.get_severity_score(classification),
            "context_verified": classification.get("top_confidence", 0) > 0.5
        }
