"""Refresh sentinel/cwe/data/cwe_web_relevant.json from the live MITRE CWE catalog.

Standalone maintenance script — not imported by the running platform, and
not exercised by the test suite (it needs live network access to
cwe.mitre.org, which this build environment does not have). Run manually
whenever a new CWE release should be pulled in:

    python scripts/fetch_cwe_data.py

Downloads the official CWE XML export (cwec_latest.xml.zip), parses it with
the stdlib xml.etree.ElementTree (no new heavy XML dependency), keeps only
weaknesses/categories whose name matches a web-application-relevant keyword
and does not match a hardware/firmware/memory-corruption/embedded-systems
exclusion keyword, and overwrites the curated dataset file.
"""
from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import httpx

CWE_XML_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "sentinel" / "cwe" / "data" / "cwe_web_relevant.json"
DOWNLOAD_TIMEOUT_SECONDS = 60.0
MIN_ACCEPTABLE_ENTRY_COUNT = 50

# Any of these substrings appearing in a weakness/category Name (lowercased)
# excludes it outright, regardless of whether an include keyword also
# matches. This is what keeps hardware/firmware/memory-corruption/embedded
# weaknesses out even though some of their names share words with web CWEs.
EXCLUDE_KEYWORDS: tuple[str, ...] = (
    "buffer overflow", "buffer over-read", "buffer under-read", "buffer underflow",
    "buffer copy", "buffer access", "out-of-bounds", "out of bounds",
    "use after free", "use-after-free", "double free", "double-free",
    "pointer", "memory allocation", "memory buffer", "null pointer dereference",
    "stack overflow", "heap overflow", "integer underflow",
    "firmware", "hardware", "physical", "side-channel", "side channel",
    "electromagnetic", "power consumption", "power analysis",
    "ics", "scada", "plc ", "embedded", "radio frequency", "rf identification",
    "sensor", "circuit", "register", "debug port", "jtag", "system-on-chip",
    "bus ", "voltage", "clock", "dma ", "bios", "uefi", "kernel driver",
    "device driver", "compiler", "assembly", "hardware logic",
)

# A weakness/category is kept if its Name matches at least one of these
# substrings (and survives EXCLUDE_KEYWORDS above).
INCLUDE_KEYWORDS: tuple[str, ...] = (
    "injection", "sql", "command", "ldap", "xpath", "xquery",
    "xml external entity", "xxe", "entity expansion", "crlf",
    "response splitting", "template engine", "expression language",
    "code injection", "eval", "resource injection",
    "cross-site scripting", "script-related", "xss",
    "authentication", "session", "password", "credential", "certificate",
    "authorization", "access control", "privilege", "permission", "ownership",
    "forced browsing", "workflow", "business logic",
    "server-side request forgery", "ssrf", "confused deputy",
    "deserialization", "untrusted control sphere",
    "configuration", "default cred", "debug", "directory listing", "cookie",
    "cryptographic", "encryption", "insufficiently random", "entropy",
    "cleartext", "csrf", "cross-site request forgery",
    "redirection to untrusted site", "open redirect",
    "path traversal", "pathname to a restricted directory", "file name or path",
    "file upload", "uploaded file",
    "race condition", "toctou", "time-of-check",
    "resource consumption", "throttling", "interaction frequency",
    "amplification", "uncontrolled recursion", "unmaintained third party",
    "known vulnerable", "vulnerable components",
    "clickjacking", "rendered ui layers", "ui misrepresentation",
    "cross-domain policy", "origin validation",
    "dynamically-determined object attributes", "object prototype attributes",
    "sensitive information", "sensitive data", "sensitive system information",
    "observable discrepancy", "observable response", "observable behavioral",
    "observable timing", "log file", "sent data", "source code",
    "improper input validation", "specified quantity", "array index",
    "specified type of input", "unsafe equivalence", "encoding error",
    "integer overflow", "missing authentication", "excessive authentication",
    "wsdl", "single-factor authentication", "single factor",
)


def download_cwe_xml(url: str = CWE_XML_ZIP_URL, *, timeout: float = DOWNLOAD_TIMEOUT_SECONDS) -> str:
    """Fetches the CWE catalog zip and returns the decoded XML text inside it."""
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
        if not xml_names:
            raise RuntimeError(f"No .xml file found inside archive downloaded from {url}")
        return archive.read(xml_names[0]).decode("utf-8")


def _local_tag(element: ElementTree.Element) -> str:
    """Strips the XML namespace prefix so parsing doesn't break across CWE schema versions."""
    return element.tag.rsplit("}", 1)[-1]


def _find_children(element: ElementTree.Element, local_name: str) -> list[ElementTree.Element]:
    return [child for child in element if _local_tag(child) == local_name]


def _is_web_relevant(name: str) -> bool:
    lowered = name.lower()
    if any(keyword in lowered for keyword in EXCLUDE_KEYWORDS):
        return False
    return any(keyword in lowered for keyword in INCLUDE_KEYWORDS)


_CATEGORY_KEYWORD_ORDER: tuple[tuple[str, str], ...] = (
    ("cross-site scripting", "xss"),
    ("script-related", "xss"),
    ("cross-site request forgery", "csrf"),
    ("csrf", "csrf"),
    ("server-side request forgery", "ssrf"),
    ("ssrf", "ssrf"),
    ("confused deputy", "ssrf"),
    ("deserialization", "deserialization"),
    ("untrusted control sphere", "deserialization"),
    ("redirection to untrusted site", "open_redirect"),
    ("open redirect", "open_redirect"),
    ("path traversal", "path_traversal"),
    ("pathname to a restricted directory", "path_traversal"),
    ("file name or path", "path_traversal"),
    ("upload", "file_upload"),
    ("race condition", "race_condition"),
    ("toctou", "race_condition"),
    ("time-of-check", "race_condition"),
    ("resource consumption", "resource_exhaustion"),
    ("throttling", "resource_exhaustion"),
    ("interaction frequency", "resource_exhaustion"),
    ("amplification", "resource_exhaustion"),
    ("uncontrolled recursion", "resource_exhaustion"),
    ("unmaintained third party", "outdated_components"),
    ("known vulnerable", "outdated_components"),
    ("vulnerable components", "outdated_components"),
    ("clickjacking", "clickjacking"),
    ("rendered ui layers", "clickjacking"),
    ("ui misrepresentation", "clickjacking"),
    ("cross-domain policy", "cors"),
    ("origin validation", "cors"),
    ("dynamically-determined object attributes", "mass_assignment"),
    ("object prototype attributes", "mass_assignment"),
    ("sensitive information", "information_exposure"),
    ("sensitive data", "information_exposure"),
    ("sensitive system information", "information_exposure"),
    ("observable discrepancy", "information_exposure"),
    ("observable response", "information_exposure"),
    ("observable behavioral", "information_exposure"),
    ("observable timing", "information_exposure"),
    ("log file", "information_exposure"),
    ("sent data", "information_exposure"),
    ("source code", "information_exposure"),
    ("cryptographic", "cryptographic"),
    ("encryption", "cryptographic"),
    ("insufficiently random", "cryptographic"),
    ("entropy", "cryptographic"),
    ("cleartext", "cryptographic"),
    ("cookie", "auth_session"),
    ("session", "auth_session"),
    ("password", "auth_session"),
    ("credential", "auth_session"),
    ("certificate", "auth_session"),
    ("single-factor authentication", "auth_session"),
    ("single factor", "auth_session"),
    ("authentication", "auth_session"),
    ("authorization", "access_control"),
    ("access control", "access_control"),
    ("privilege", "access_control"),
    ("permission", "access_control"),
    ("ownership", "access_control"),
    ("forced browsing", "access_control"),
    ("workflow", "business_logic"),
    ("business logic", "business_logic"),
    ("configuration", "misconfiguration"),
    ("default cred", "misconfiguration"),
    ("debug", "misconfiguration"),
    ("directory listing", "misconfiguration"),
    ("specified quantity", "input_validation"),
    ("array index", "input_validation"),
    ("specified type of input", "input_validation"),
    ("unsafe equivalence", "input_validation"),
    ("encoding error", "input_validation"),
    ("integer overflow", "input_validation"),
    ("improper input validation", "input_validation"),
    ("missing authentication", "api_security"),
    ("excessive authentication", "api_security"),
    ("wsdl", "api_security"),
    ("injection", "injection"),
    ("sql", "injection"),
    ("command", "injection"),
    ("ldap", "injection"),
    ("xpath", "injection"),
    ("xquery", "injection"),
    ("xml external entity", "injection"),
    ("xxe", "injection"),
    ("entity expansion", "injection"),
    ("crlf", "injection"),
    ("response splitting", "injection"),
    ("template engine", "injection"),
    ("expression language", "injection"),
    ("code injection", "injection"),
    ("eval", "injection"),
)


def _category_for(name: str) -> str:
    lowered = name.lower()
    for keyword, category in _CATEGORY_KEYWORD_ORDER:
        if keyword in lowered:
            return category
    return "uncategorized"


def parse_cwe_entries(xml_text: str) -> list[dict]:
    """Parses the CWE catalog XML into web-relevant {cwe_id, name, category} dicts.

    Pulls from both <Weaknesses><Weakness> (individual weaknesses) and
    <Categories><Category> (grouping nodes, e.g. the OWASP-mapped category
    IDs like CWE-937/CWE-1035) since the curated dataset draws from both.
    """
    root = ElementTree.fromstring(xml_text)
    entries: dict[str, dict] = {}

    for container_name, node_name in (("Weaknesses", "Weakness"), ("Categories", "Category")):
        for container in _find_children(root, container_name):
            for node in _find_children(container, node_name):
                cwe_id_raw = node.get("ID")
                name = node.get("Name")
                if not cwe_id_raw or not name:
                    continue
                if not _is_web_relevant(name):
                    continue
                full_id = f"CWE-{cwe_id_raw}"
                entries[full_id] = {
                    "cwe_id": full_id,
                    "name": name,
                    "category": _category_for(name),
                }

    return sorted(entries.values(), key=lambda entry: int(entry["cwe_id"].split("-")[1]))


def main() -> int:
    print(f"Downloading {CWE_XML_ZIP_URL} ...", file=sys.stderr)
    xml_text = download_cwe_xml()

    print("Parsing CWE catalog XML ...", file=sys.stderr)
    entries = parse_cwe_entries(xml_text)

    if len(entries) < MIN_ACCEPTABLE_ENTRY_COUNT:
        print(
            f"Only {len(entries)} web-relevant CWEs matched — refusing to overwrite "
            f"{OUTPUT_PATH} with a suspiciously small dataset (keyword filters may need updating).",
            file=sys.stderr,
        )
        return 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
        f.write("\n")

    print(f"Wrote {len(entries)} entries to {OUTPUT_PATH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
