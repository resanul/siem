"""
OpenSOC Forge - Global Cyber Threat News & Forum Intelligence Service.
Aggregates and caches live threat intelligence feeds from top cybersecurity newsrooms and forums:
- The Hacker News (THN)
- SecurityWeek
- Dark Reading
- Krebs on Security
- SANS Internet Storm Center (ISC) Diary
- Help Net Security
- Reddit r/netsec
"""

import time
import re
import html
import logging
import urllib.request
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("threat_news_service")

# Feed Sources Definition
FEED_SOURCES = [
    {
        "id": "thn",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "fallback_url": "https://thehackernews.com/rss.xml",
        "color": "#ef4444", # Red
        "badge": "THN",
        "type": "rss"
    },
    {
        "id": "securityweek",
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "color": "#3b82f6", # Blue
        "badge": "SECWEEK",
        "type": "rss"
    },
    {
        "id": "darkreading",
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "color": "#a855f7", # Purple
        "badge": "DARKREADING",
        "type": "rss"
    },
    {
        "id": "krebsonsecurity",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "color": "#eab308", # Amber/Yellow
        "badge": "KREBS",
        "type": "rss"
    },
    {
        "id": "sans_isc",
        "name": "SANS ISC Diary",
        "url": "https://isc.sans.edu/rssfeed.xml",
        "color": "#06b6d4", # Cyan
        "badge": "SANS ISC",
        "type": "rss"
    },
    {
        "id": "helpnetsecurity",
        "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/",
        "color": "#10b981", # Emerald
        "badge": "HELPNET",
        "type": "rss"
    },
    {
        "id": "reddit_netsec",
        "name": "Reddit r/netsec",
        "url": "https://www.reddit.com/r/netsec/.rss",
        "color": "#f97316", # Orange
        "badge": "r/netsec",
        "type": "atom"
    }
]

# Cache structure
_NEWS_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "items": []
}
CACHE_TTL_SECONDS = 600  # 10 minutes cache


def _clean_html_text(text: str) -> str:
    """Strips HTML tags and decodes entities."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = html.unescape(clean)
    return " ".join(clean.split()).strip()


def _classify_threat_category(title: str, summary: str) -> str:
    """Classifies news items into SIEM threat taxonomy."""
    text = f"{title} {summary}".lower()
    if any(k in text for k in ["ransomware", "encryptor", "lockbit", "blackcat", "akira"]):
        return "RANSOMWARE"
    if any(k in text for k in ["zero-day", "0-day", "exploit", "cve-", "flaw", "vulnerability", "rce", "patch"]):
        return "EXPLOIT / CVE"
    if any(k in text for k in ["apt", "nation-state", "espionage", "russian", "chinese", "iranian", "north korea"]):
        return "APT / THREAT ACTOR"
    if any(k in text for k in ["malware", "trojan", "infostealer", "botnet", "backdoor", "rootkit"]):
        return "MALWARE / C2"
    if any(k in text for k in ["phishing", "credential", "mfa", "identity", "active directory", "kerberos"]):
        return "IDENTITY / AUTH"
    if any(k in text for k in ["ddos", "flood", "amplification"]):
        return "DDOS"
    if any(k in text for k in ["bank", "fintech", "financial", "atm", "swift", "crypto", "bitcoin"]):
        return "FINANCIAL THREAT"
    return "CYBER INTEL"


def _extract_image_url(item_xml: ET.Element, desc: str) -> Optional[str]:
    """Attempts to extract featured thumbnail/media URL."""
    # Check media:content or media:thumbnail
    for child in item_xml:
        tag = child.tag.lower()
        if "content" in tag or "thumbnail" in tag:
            u = child.attrib.get("url")
            if u:
                return u
        if "enclosure" in tag:
            u = child.attrib.get("url")
            if u and child.attrib.get("type", "").startswith("image"):
                return u

    # Check img tag inside description
    img_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', desc)
    if img_match:
        return img_match.group(1)

    return None


def _parse_pub_date(pub_str: str) -> Tuple[str, int]:
    """Converts RSS pubDate or Atom updated date into ISO 8601 string and epoch seconds."""
    if not pub_str:
        now = datetime.now(timezone.utc)
        return now.isoformat(), int(now.timestamp())

    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(pub_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat(), int(dt.timestamp())
    except Exception:
        pass

    try:
        clean = pub_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat(), int(dt.timestamp())
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    return now.isoformat(), int(now.timestamp())



def fetch_source_feed(source: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fetches and parses a single RSS or Atom feed."""
    items_out: List[Dict[str, Any]] = []
    url = source["url"]
    source_name = source["name"]
    source_id = source["id"]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    urls_to_try = [source["url"]]
    if source.get("fallback_url"):
        urls_to_try.append(source["fallback_url"])

    content = None
    for target_url in urls_to_try:
        ua = "OpenSOC-Forge-SecFeed/1.0 (Enterprise SOC; contact@opensoc.org)" if "reddit" in target_url else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OpenSOC-Forge/1.0"
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": ua,
                "Accept": "application/rss+xml, application/xml, text/xml, application/atom+xml, */*"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=7.0, context=ctx) as resp:
                content = resp.read()
                if content:
                    break
        except Exception:
            continue

    if not content:
        logger.warning(f"Failed to fetch feed for {source_name}")
        return items_out

    try:
        root = ET.fromstring(content)

        if source["type"] == "atom" or root.tag.endswith("feed"):
            # Atom parser (e.g. Reddit r/netsec)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            entries = root.findall("atom:entry", ns) or root.findall("entry")
            for entry in entries[:15]:
                title = _clean_html_text(entry.findtext("atom:title", default="", namespaces=ns) or entry.findtext("title") or "")
                link_elem = entry.find("atom:link", ns) or entry.find("link")
                link = link_elem.attrib.get("href") if link_elem is not None else ""
                updated = entry.findtext("atom:updated", default="", namespaces=ns) or entry.findtext("updated") or ""
                summary_raw = entry.findtext("atom:content", default="", namespaces=ns) or entry.findtext("content") or entry.findtext("summary") or ""
                summary = _clean_html_text(summary_raw)[:240]

                if not title or not link:
                    continue

                iso_date, epoch_ts = _parse_pub_date(updated)
                category = _classify_threat_category(title, summary)

                items_out.append({
                    "id": f"{source_id}-{epoch_ts}-{abs(hash(title)) % 100000}",
                    "source_id": source_id,
                    "source_name": source_name,
                    "source_color": source["color"],
                    "source_badge": source["badge"],
                    "title": title,
                    "link": link,
                    "published_at": iso_date,
                    "epoch_time": epoch_ts,
                    "summary": summary,
                    "category": category,
                    "image_url": None
                })
        else:
            # Standard RSS parser
            channel = root.find("channel")
            if channel is None:
                channel = root

            entries = channel.findall("item")
            for item in entries[:20]:
                title = _clean_html_text(item.findtext("title") or "")
                link = (item.findtext("link") or "").strip()
                pub_date_str = item.findtext("pubDate") or ""
                desc_raw = item.findtext("description") or ""
                summary = _clean_html_text(desc_raw)[:240]

                if not title or not link:
                    continue

                iso_date, epoch_ts = _parse_pub_date(pub_date_str)
                category = _classify_threat_category(title, summary)
                image_url = _extract_image_url(item, desc_raw)

                items_out.append({
                    "id": f"{source_id}-{epoch_ts}-{abs(hash(title)) % 100000}",
                    "source_id": source_id,
                    "source_name": source_name,
                    "source_color": source["color"],
                    "source_badge": source["badge"],
                    "title": title,
                    "link": link,
                    "published_at": iso_date,
                    "epoch_time": epoch_ts,
                    "summary": summary,
                    "category": category,
                    "image_url": image_url
                })

    except Exception as exc:
        logger.warning(f"Failed to fetch feed for {source_name} ({url}): {exc}")

    return items_out


def get_all_threat_news(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Returns aggregated cyber threat intelligence news from all supported sources.
    Uses in-memory cache to guarantee sub-millisecond responses on dashboard renders.
    """
    global _NEWS_CACHE
    now = time.time()

    if not force_refresh and _NEWS_CACHE["items"] and (now - _NEWS_CACHE["timestamp"] < CACHE_TTL_SECONDS):
        return _NEWS_CACHE["items"]

    all_items: List[Dict[str, Any]] = []

    # Parallel or sequential fetch with short timeouts
    for src in FEED_SOURCES:
        try:
            feed_items = fetch_source_feed(src)
            all_items.extend(feed_items)
        except Exception:
            pass

    # Sort descending by published epoch time (newest first)
    all_items.sort(key=lambda x: x.get("epoch_time", 0), reverse=True)

    _NEWS_CACHE = {
        "timestamp": now,
        "items": all_items
    }
    return all_items
