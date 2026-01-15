import sys
import unittest
from modules.ai_analyzer import AIAnalyzer

class TestAnalyzer(unittest.TestCase):
    def test_detection(self):
        analyzer = AIAnalyzer()
        content = {"text": "My AWS key is AKIA1234567890ABCDEF and email is test@example.com"}
        findings = analyzer.analyze(content)
        
        types = [f["type"] for f in findings]
        self.assertIn("aws_key", types)
        self.assertIn("email", types)
        print("Test detection passed!")

if __name__ == "__main__":
    unittest.main()
