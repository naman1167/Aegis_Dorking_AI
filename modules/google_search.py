import os
from googleapiclient.discovery import build
from dotenv import load_dotenv

load_dotenv()

def google_search(query, api_key=None, cse_id=None, num_results=10):
    """
    Performs a Google Search using the Custom Search API.
    Returns a list of URLs.
    """
    api_key = api_key or os.getenv("GOOGLE_API_KEY")
    cse_id = cse_id or os.getenv("GOOGLE_CSE_ID")

    if not api_key or not cse_id:
        print("[!] Google API Key or CSE ID missing. Search disabled.")
        return []

    try:
        service = build("customsearch", "v1", developerKey=api_key)
        res = service.cse().list(q=query, cx=cse_id, num=num_results).execute()
        
        urls = []
        if 'items' in res:
            for item in res['items']:
                urls.append(item['link'])
        return urls
    except Exception as e:
        print(f"[!] Error during Google Search: {e}")
        return []
