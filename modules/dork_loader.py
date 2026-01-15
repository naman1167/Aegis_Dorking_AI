import os

def load_dorks(file_path):
    """
    Loads Google Dorks from a text file.
    Dorks are cleaned (whitespace removed) and empty/commented lines are skipped.
    """
    if not os.path.exists(file_path):
        print(f"[!] Dork file not found: {file_path}")
        return []

    dorks = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            dorks.append(line)
    
    return dorks
