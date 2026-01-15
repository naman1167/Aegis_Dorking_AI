import pytest
from modules.ai_analyzer import AIAnalyzer

def test_ai_analyzer_sensitive_data():
    analyzer = AIAnalyzer()
    
    test_content = {
        "text": "My email is test@example.com and my AWS key is AKIA1234567890ABCDEF. Also, here is a secret: password='super_secret_123'."
    }
    
    findings = analyzer.analyze(test_content)
    
    # Check for email
    assert any(f["type"] == "email" and "test@example.com" in f["match"] for f in findings)
    
    # Check for AWS key
    assert any(f["type"] == "aws_key" and "AKIA1234567890ABCDEF" in f["match"] for f in findings)
    
    # Check for password patterns
    assert any(f["type"] == "password_alike" and "super_secret_123" in f["match"] for f in findings)

def test_ai_analyzer_sql_dump():
    analyzer = AIAnalyzer()
    test_content = {
        "text": "CREATE TABLE users (id INT, username TEXT); INSERT INTO users VALUES (1, 'admin');"
    }
    findings = analyzer.analyze(test_content)
    assert any(f["type"] == "sql_dump" for f in findings)
