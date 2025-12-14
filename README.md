# URL extraction from emails
Using Marketo REST APIs to fetch all the URLs currently being used in Marketo email


#!/usr/bin/env python3
"""
Marketo Email URL Extractor
- Authenticates using client credentials
- Lists email metadata (with pagination)
- Fetches full content of a selected email
- Extracts URLs and saves to a text file

Usage:
  export MARKETO_CLIENT_ID="e98fa865-2be5-4c9f-8454-d667f4b7c6a5"
  export MARKETO_CLIENT_SECRET="Yr6T98EvBqHnKZNmsLIJhMsUeepzkDMv"
  python marketo_email_urls.py --host 643-sts-510.mktorest.com --email-id 1116 --out urls.txt

If --email-id is omitted, the script will pick the first email from the listing.
"""

import os
import re
import sys
import time
import html
import json
import argparse
from typing import List, Dict, Tuple, Optional

import requests

# ---------------------------
# Configuration & Constants
# ---------------------------
DEFAULT_LIMIT = 200  # Marketo typically allows up to 200 items per page for Asset APIs
RETRY_STATUS = {429, 503}  # basic retry on rate limit/unavailable
MAX_RETRIES = 5
BACKOFF_SECONDS = 2

URL_REGEX = re.compile(r'''(?i)\b((?:https?://|www\.)[^\s<>"'()]+)''')

# ---------------------------
# HTTP helpers
# ---------------------------
def http_get(session: requests.Session, url: str, headers: Dict[str, str], params: Dict[str, str] = None) -> Dict:
    """GET with simple retry/backoff."""
    for attempt in range(1, MAX_RETRIES + 1):
        resp = session.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code in RETRY_STATUS:
            wait = BACKOFF_SECONDS * attempt
            print(f"[warn] HTTP {resp.status_code}, retrying in {wait}s (attempt {attempt}/{MAX_RETRIES})...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    # Final try without backoff to raise for_status
    resp = session.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def http_post_form(session: requests.Session, url: str, data: Dict[str, str], headers: Dict[str, str]) -> Dict:
    """POST form with basic retry/backoff."""
    for attempt in range(1, MAX_RETRIES + 1):
        resp = session.post(url, headers=headers, data=data, timeout=30)
        if resp.status_code in RETRY_STATUS:
            wait = BACKOFF_SECONDS * attempt
            print(f"[warn] HTTP {resp.status_code}, retrying in {wait}s (attempt {attempt}/{MAX_RETRIES})...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    resp = session.post(url, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()

# ---------------------------
# Marketo API Wrappers
# ---------------------------
def get_access_token(host: str, client_id: str, client_secret: str) -> str:
    """Obtain OAuth access token from Marketo identity endpoint."""
    token_url = f"https://{host}/identity/oauth/token"
    session = requests.Session()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    print(f"[info] Authenticating at {token_url} ...")
    res = http_post_form(session, token_url, data=data, headers=headers)
    # Expected shape: {"access_token":"...", "token_type":"bearer", "expires_in":...}
    token = res.get("access_token")
    if not token:
        raise RuntimeError("Failed to obtain access_token. Response:\n" + json.dumps(res, indent=2))
    print("[info] Access token acquired.")
    return token

def list_emails(host: str, access_token: str, limit: int = DEFAULT_LIMIT) -> List[Dict]:
    """List email asset metadata with pagination."""
    session = requests.Session()
    base_url = f"https://{host}/rest/asset/v1/emails.json"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    emails: List[Dict] = []
    offset = 0

    while True:
        params = {"offset": offset, "limit": limit}
        print(f"[info] Fetching emails offset={offset}, limit={limit} ...")
        data = http_get(session, base_url, headers=headers, params=params)

        # Typical Marketo response:
        # { "success": true, "requestId":"...", "result":[...], "moreResult": true/false }
        result = data.get("result") or []
        emails.extend(result)
        more = data.get("moreResult", False)

        print(f"[info] Retrieved {len(result)} emails; total so far: {len(emails)}")
        if not more or not result:
            break

        offset += len(result)

    return emails

def get_email_full_content(host: str, access_token: str, email_id: int) -> Dict:
    """Fetch full content for a specific email asset."""
    session = requests.Session()
    url = f"https://{host}/rest/asset/v1/email/{email_id}/fullContent.json"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    print(f"[info] Fetching full content for email id={email_id} ...")
    data = http_get(session, url, headers=headers)

    # Expected shapes vary; try common patterns:
    # - {"success":true, "result":[{"id":1116,"html":"<html>..</html>","text":".."}]}
    # - {"success":true, "result":[{"fullContent":"<html>..</html>"}]}
    # - {"success":true, "result":[{"content":"<html>..</html>"}]}
    result = (data.get("result") or [])
    if not result:
        raise RuntimeError("No 'result' in fullContent response:\n" + json.dumps(data, indent=2))
    item = result[0]

    # Extract HTML/text content with fallbacks
    body_html = item.get("html") or item.get("fullContent") or item.get("content")
    body_text = item.get("text")
    if not body_html and not body_text:
        # Some tenants store content under nested keys (rare). Dump for debugging.
        raise RuntimeError("Could not find html/text/fullContent/content in response:\n" + json.dumps(item, indent=2))

    return {"html": body_html, "text": body_text}

# ---------------------------
# URL Extraction Utilities
# ---------------------------
def clean_url(u: str) -> str:
    u = u.strip()
    if u.startswith("www."):
        u = "https://" + u
    # Strip trailing punctuation common in emails
    u = u.rstrip('.,;!?)"\'')
    return u

def extract_urls_from_html_or_text(html_text: Optional[str], plain_text: Optional[str]) -> List[str]:
    urls = set()

    # 1) Regex over HTML content (raw)
    if html_text:
        for m in URL_REGEX.findall(html_text):
            urls.add(clean_url(m))
        # 2) Extract href attributes
        href_regex = re.compile(r'href\s*=\s*"\'["\']', re.IGNORECASE)
        for href in href_regex.findall(html_text):
            urls.add(clean_url(html.unescape(href)))

    # 3) Regex over plain text fallback
    if plain_text:
        for m in URL_REGEX.findall(plain_text):
            urls.add(clean_url(m))

    # Basic de-dup and sort
    return sorted(urls)

def save_urls(urls: List[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u + "\n")
    print(f"[info] Saved {len(urls)} URL(s) to {path}")

# ---------------------------
# CLI
# ---------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Extract URLs from a Marketo email body.")
    parser.add_argument("--host", required=True, help="Marketo host (e.g., 643-sts-510.mktorest.com)")
    parser.add_argument("--email-id", type=int, help="Email asset ID (if omitted, first listed email is used)")
    parser.add_argument("--out", default="email_urls.txt", help="Output file path for URLs")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Page size when listing emails")
    parser.add_argument("--use-cookie", action="store_true", help="Include COOKIE header from env var COOKIE if required by your network")
    return parser.parse_args()

def main():
    args = parse_args()
    client_id = os.getenv("MARKETO_CLIENT_ID")
    client_secret = os.getenv("MARKETO_CLIENT_SECRET")
    if not client_id or not client_secret:
        print("[error] Please set MARKETO_CLIENT_ID and MARKETO_CLIENT_SECRET environment variables.")
        sys.exit(1)

    # 1) Auth
    token = get_access_token(args.host, client_id, client_secret)

    # 2) List emails (metadata)
    emails = list_emails(args.host, token, limit=args.limit)
    if not emails:
        print("[error] No emails returned.")
        sys.exit(1)

    # Show one example item for transparency
    print("[info] Example email metadata item:")
    print(json.dumps(emails[0], indent=2))

    # 3) Determine email_id to fetch
    email_id = args.email_id if args.email_id is not None else emails[0].get("id")
    if not email_id:
        print("[error] Could not determine email_id from metadata. Inspect 'result' structure.")
        sys.exit(1)

    # 4) Fetch full content
    content = get_email_full_content(args.host, token, email_id)
    html_body = content.get("html")
    text_body = content.get("text")

    # 5) Extract URLs
    urls = extract_urls_from_html_or_text(html_body, text_body)
    print(f"[info] Found {len(urls)} URL(s):")
    for u in urls:
        print(" -", u)

    # 6) Save to file
    save_urls(urls, args.out)

if __name__ == "__main__":
    main()

