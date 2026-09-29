import re
import requests
from bs4 import BeautifulSoup

OFFICIAL_SOURCES = {
    "nmap": {
        "name": "Nmap",
        "url": "https://nmap.org/changelog.html",
        "download": "https://nmap.org/download.html",
    },
}

FRESHNESS_WORDS = re.compile(
    r"\b(latest|current|newest|recent|new release|release|version|"
    r"changelog|what's new|whats new|updated|update)\b",
    re.IGNORECASE,
)


def needs_freshness_check(text):
    return bool(FRESHNESS_WORDS.search(text or ""))


def detect_tool(text):
    text = (text or "").lower()

    if re.search(r"\bnmap\b", text):
        return "nmap"

    return None


def verify_nmap():
    source = OFFICIAL_SOURCES["nmap"]

    try:
        response = requests.get(
            source["url"],
            timeout=15,
            headers={
                "User-Agent": "Ghost-AI-Freshness-Checker/1.0"
            },
        )
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Extract the visible changelog text.
        text = soup.get_text(" ", strip=True)

        # Nmap's official changelog contains entries such as:
        # Nmap 7.991 [2026-08-06]
        releases = re.findall(
            r"Nmap\s+([0-9]+\.[0-9]+)\s*\[([0-9]{4}-[0-9]{2}-[0-9]{2})\]",
            text,
            re.IGNORECASE,
        )

        if not releases:
            return {
                "verified": False,
                "tool": "Nmap",
                "message": "Official Nmap changelog was reached, but no release entry could be parsed.",
                "source": source["url"],
            }

        version, date = releases[0]

        return {
            "verified": True,
            "tool": "Nmap",
            "latest_version": version,
            "release_date": date,
            "source": source["url"],
            "download": source["download"],
        }

    except Exception as exc:
        return {
            "verified": False,
            "tool": "Nmap",
            "message": f"Official-source verification failed: {exc}",
            "source": source["url"],
        }


def verify_freshness(user_text):
    if not needs_freshness_check(user_text):
        return None

    tool = detect_tool(user_text)

    if tool == "nmap":
        return verify_nmap()

    return {
        "verified": False,
        "tool": tool,
        "message": (
            "This is a freshness-sensitive question, but Ghost has no "
            "official-source verifier configured for this tool yet."
        ),
    }


def build_verification_context(result):
    if not result:
        return ""

    if result.get("verified"):
        return f"""
FRESHNESS VERIFICATION RESULT

Tool: {result['tool']}
Latest verified version: {result['latest_version']}
Release date: {result['release_date']}
Official changelog: {result['source']}
Official downloads: {result['download']}

IMPORTANT:
- Treat these values as the authoritative current facts.
- Do not claim an older version is the latest.
- Do not invent features.
- If discussing additional features, distinguish verified changelog facts
  from general knowledge.
"""

    return f"""
FRESHNESS VERIFICATION

Ghost could not verify the current release information.

Tool: {result.get('tool')}
Reason: {result.get('message')}

Do NOT pretend that the information is current.
Clearly state that current information could not be verified.
"""
