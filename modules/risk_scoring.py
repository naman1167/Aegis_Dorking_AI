def calculate_risk_score(findings, config):
    """
    Calculates a risk score based on findings, weights from config, 
    and AI/ML confidence levels if available.
    Returns (score, level)
    """
    weights = config.get("scoring", {}).get("weights", {})
    max_score = config.get("scoring", {}).get("max_score", 100)
    
    total_score = 0
    unique_types = set()

    for finding in findings:
        ftype = finding["type"]
        base_weight = weights.get(ftype, 10)
        
        # Adjust weight based on ML confidence if present
        confidence = finding.get("confidence", 1.0) # Default to 1.0 for regex
        
        # If ML verified it as low severity or low confidence, reduce weight
        if "ml_verification" in finding:
            ml_data = finding["ml_verification"]
            if ml_data.get("severity") == "LOW":
                confidence *= 0.5
            if not ml_data.get("context_verified", True):
                confidence *= 0.3
        
        # Apply confidence-weighted score
        total_score += base_weight * confidence
        unique_types.add(ftype)

    # Simplified categorization
    score = int(min(total_score, max_score))
    
    if score >= 75:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"
        
    return score, level
