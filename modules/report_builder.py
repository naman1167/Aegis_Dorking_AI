import json
import pandas as pd
import os
from datetime import datetime

def generate_reports(results, output_dir):
    """
    Generates JSON and CSV reports from scan results.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"report_{timestamp}.json")
    csv_path = os.path.join(output_dir, f"report_{timestamp}.csv")

    # JSON Report
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)

    # CSV Report Flattening
    flat_data = []
    for entry in results:
        url = entry.get("url")
        score = entry.get("risk_score")
        level = entry.get("risk_level")
        for finding in entry.get("findings", []):
            flat_data.append({
                "timestamp": timestamp,
                "url": url,
                "risk_score": score,
                "risk_level": level,
                "finding_type": finding["type"],
                "match": finding["match"],
                "context": finding["context"]
            })

    if flat_data:
        df = pd.DataFrame(flat_data)
        df.to_csv(csv_path, index=False)
    
    return json_path, csv_path
