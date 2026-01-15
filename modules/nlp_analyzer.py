import spacy
from typing import List, Dict, Any

class NLPAnalyzer:
    """
    NLP-based analyzer using spaCy for Named Entity Recognition and linguistic analysis.
    """
    
    def __init__(self):
        try:
            self.nlp = spacy.load("en_core_web_sm")
            print("[+] NLP model loaded successfully")
        except Exception as e:
            print(f"[!] Failed to load spaCy model: {e}")
            self.nlp = None
    
    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract named entities from text using NLP.
        Returns organizations, people, dates, technologies, etc.
        """
        if not self.nlp:
            return []
        
        entities = []
        doc = self.nlp(text[:100000])  # Limit text length for performance
        
        for ent in doc.ents:
            entities.append({
                "text": ent.text,
                "label": ent.label_,
                "start": ent.start_char,
                "end": ent.end_char,
                "context": text[max(0, ent.start_char-50):min(len(text), ent.end_char+50)]
            })
        
        return entities
    
    def find_credentials_context(self, text: str) -> List[Dict[str, Any]]:
        """
        Use NLP to find credential-related contexts beyond regex.
        Looks for linguistic patterns like "password is", "key:", etc.
        """
        if not self.nlp:
            return []
        
        findings = []
        doc = self.nlp(text[:50000])
        
        # Credential-related keywords
        credential_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token',
            'api_key', 'apikey', 'credential', 'auth', 'authorization',
            'access_token', 'refresh_token', 'private_key', 'secret_key'
        ]
        
        for token in doc:
            # Check if token is credential-related
            if token.text.lower() in credential_keywords:
                # Get surrounding context
                start = max(0, token.i - 10)
                end = min(len(doc), token.i + 10)
                context_tokens = doc[start:end]
                
                # Look for assignment patterns
                for i, t in enumerate(context_tokens):
                    if t.text in ['=', ':', 'is']:
                        findings.append({
                            "type": "credential_context",
                            "keyword": token.text,
                            "context": context_tokens.text,
                            "confidence": 0.7
                        })
                        break
        
        return findings
    
    def detect_sensitive_patterns(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect sensitive information using linguistic patterns and NLP.
        """
        if not self.nlp:
            return []
        
        findings = []
        doc = self.nlp(text[:50000])
        
        # Look for emails in entities
        for ent in doc.ents:
            if ent.label_ == "ORG":
                # Check if organization name appears with sensitive keywords
                context_start = max(0, ent.start_char - 100)
                context_end = min(len(text), ent.end_char + 100)
                context = text[context_start:context_end].lower()
                
                if any(keyword in context for keyword in ['database', 'admin', 'root', 'config']):
                    findings.append({
                        "type": "sensitive_organization",
                        "organization": ent.text,
                        "context": context,
                        "confidence": 0.6
                    })
        
        return findings
    
    def analyze(self, content: Dict[str, str]) -> Dict[str, Any]:
        """
        Main analysis method combining all NLP techniques.
        """
        text = content.get("text", "")
        
        results = {
            "entities": self.extract_entities(text),
            "credential_contexts": self.find_credentials_context(text),
            "sensitive_patterns": self.detect_sensitive_patterns(text),
            "nlp_enabled": self.nlp is not None
        }
        
        return results
