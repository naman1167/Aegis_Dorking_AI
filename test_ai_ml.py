from modules.ai_analyzer import AIAnalyzer
import os

def test_new_analyzer():
    print("[*] Testing AIAnalyzer with ML/NLP integration...")
    analyzer = AIAnalyzer()
    
    # Sample content with various sensitive patterns
    sample_content = {
        "text": """
        Welcome to the project.
        Our AWS key is AKIA1234567890ABCDEF.
        Please don't share the DB_PASSWORD=super-secret-password-123.
        You can contact us at admin@example.com.
        I also have a private key:
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA75...
        -----END RSA PRIVATE KEY-----
        The database configuration seems exposed on this server.
        """
    }
    
    findings = analyzer.analyze(sample_content)
    
    print(f"\n[+] Found {len(findings)} findings:")
    for i, f in enumerate(findings, 1):
        print(f"\nFinding {i}:")
        print(f"  Type: {f.get('type')}")
        print(f"  Source: {f.get('source')}")
        print(f"  Match: {f.get('match')}")
        if 'ml_verification' in f:
            ml = f['ml_verification']
            print(f"  ML Classification: {ml.get('ml_classification')} (Conf: {ml.get('ml_confidence')})")
            print(f"  Severity: {f.get('severity')}")
            print(f"  Context Verified: {ml.get('context_verified')}")

if __name__ == "__main__":
    test_new_analyzer()
