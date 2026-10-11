"""
extractor/ner.py — Named Entity Recognition for entities without fixed patterns.

Uses spaCy (en_core_web_sm) as a module-level singleton.  If the model is not
installed the module still imports cleanly — all public functions return empty
dicts / sets and log a warning rather than raising.

Uses a bundled dictionary of 200+ malware family names for MALWARE_FAMILY and
RANSOMWARE_GROUP detection (word-bounded, case-insensitive).

Public interface
----------------
extract_named_entities(text)    → dict[str, list[str]]
load_malware_dictionary()       → set[str]
"""

from __future__ import annotations

import logging
import re

from extractor import entity_shape as _shape
from extractor import gazetteer
from extractor.software_suppression import should_suppress_organization

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NER entity type constants (supplements regex_patterns constants)
# ---------------------------------------------------------------------------

THREAT_ACTOR_HANDLE = "THREAT_ACTOR_HANDLE"
MALWARE_FAMILY = "MALWARE_FAMILY"
RANSOMWARE_GROUP = "RANSOMWARE_GROUP"
ORGANIZATION_NAME = "ORGANIZATION_NAME"

# ---------------------------------------------------------------------------
# Malware family dictionary
# ---------------------------------------------------------------------------

_MALWARE_DICT: set[str] = {
    # Ransomware families — active and historical
    "LockBit", "LockBit 2.0", "LockBit 3.0",
    "BlackCat", "ALPHV",
    "Cl0p", "Clop",
    "REvil", "Sodinokibi",
    "Conti",
    "BlackMatter",
    "Hive",
    "Vice Society",
    "Play",
    "Royal",
    "Akira",
    "BlackSuit",
    "Avaddon",
    "DarkSide",
    "Maze",
    "Ryuk",
    "Egregor",
    "Babuk",
    "DoppelPaymer",
    "MedusaLocker",
    "Prometheus",
    "Grief",
    "Ragnar Locker",
    "RagnarLocker",
    "Cuba",
    "BlackBasta",
    "Black Basta",
    "Yanluowang",
    "Quantum",
    "Monti",
    "Nokoyawa",
    "Trigona",
    "Rhysida",
    "Hunters International",
    "Cactus",
    "INC Ransom",
    "Meow",
    "MedusaBIG",
    "KillSec",
    "Dispossessor",
    "Eldorado",
    "SenSayQ",
    "RansomHub",
    "DragonForce",
    "Scattered Spider",
    "Dark Angels",
    "8Base",
    "Qilin",
    "Fog",
    "Lynx",
    "Cicada3301",
    "Embargo",
    "Karakurt",
    "LV",
    "Entropy",
    "Vice",
    "Zeppelin",
    "Dharma",
    "Phobos",
    "Xorist",
    "Globeimposter",
    "Makop",
    "Stop",
    "Djvu",
    "WannaCry",
    "WannaCryptor",
    "Petya",
    "NotPetya",
    "GoldenEye",
    "BadRabbit",
    "SamSam",
    "Cerber",
    "Locky",
    "CryptoLocker",
    "TeslaCrypt",
    "Cryptowall",
    "Jigsaw",
    "Philadelphia",
    "Stampado",
    "Shade",
    "Troldesh",
    "Reveton",
    "KeRanger",
    "Erebus",
    "Satan",
    "GandCrab",
    "Scarab",
    "GlobeImposter",
    "Sodinokibi",
    # RATs — remote access trojans
    "AsyncRAT",
    "QuasarRAT",
    "Quasar",
    "NjRAT",
    "njRAT",
    "DarkComet",
    "Remcos",
    "NetWire",
    "XWorm",
    "Warzone",
    "Warzone RAT",
    "Agent Tesla",
    "AgentTesla",
    "BitRAT",
    "RevengeRAT",
    "Orcus",
    "Gh0st",
    "Gh0stRAT",
    "Havoc",
    "Sliver",
    "Cobalt Strike",
    "CobaltStrike",
    "Metasploit",
    "Empire",
    "PowerShell Empire",
    "Mythic",
    "Brute Ratel",
    "BruteRatel",
    "PoshC2",
    "Covenant",
    "Merlin",
    "SILENTTRINITY",
    "Nishang",
    "Pupy",
    "Koadic",
    # Stealers — credential and data theft
    "RedLine",
    "Raccoon",
    "Raccoon Stealer",
    "Vidar",
    "Mars",
    "Aurora",
    "Lumma",
    "Lumma Stealer",
    "LummaC2",
    "AZORult",
    "Azorult",
    "FormBook",
    "Snake Keylogger",
    "SnakeKeylogger",
    "HawkEye",
    "Predator",
    "Predator the Thief",
    "Ducktail",
    "Rhadamanthys",
    "WhiteSnake",
    "Atomic Stealer",
    "AMOS",
    "StealC",
    "Meduza",
    "MetaStealer",
    "RisePro",
    "Mystic",
    "CryptBot",
    "Cryptbot",
    "Panda Stealer",
    "BlackGuard",
    "Titan Stealer",
    "Erbium",
    "Eternity Stealer",
    "Oski",
    "Krypton Stealer",
    "Luca Stealer",
    "Spectre Stealer",
    # Loaders — malware delivery mechanisms
    "SmokeLoader",
    "Smoke Loader",
    "IcedID",
    "Emotet",
    "QakBot",
    "Qakbot",
    "Bumblebee",
    "GootLoader",
    "PrivateLoader",
    "GuLoader",
    "CloudEyE",
    "DanaBot",
    "Amadey",
    "RCSession",
    "PureCrypter",
    "DonutLoader",
    "ModiLoader",
    "AiBotLoader",
    "Loader",
    "SystemBC",
    "Matanbuchus",
    "Gozi",
    "DBatLoader",
    "MalDoc",
    "XLoader",
    "FormBook",
    "MoqHao",
    "Pikabot",
    "Darkgate",
    "DarkGate",
    "Latrodectus",
    "WarmCookie",
    # Banking trojans
    "TrickBot",
    "Trickbot",
    "Dridex",
    "Ursnif",
    "ZLoader",
    "Zloader",
    "Gozi",
    "ISFB",
    "Ramnit",
    "Qbot",
    "QBot",
    "Shylock",
    "Kronos",
    "Zeus",
    "SpyEye",
    "Carbanak",
    "FIN7",
    "Valak",
    "BazarLoader",
    "BazarBackdoor",
    "IcedID",
    "TaurusLoader",
    "Bookworm",
    "Casbaneiro",
    "Mekotio",
    "Grandoreiro",
    "Javali",
    "Vizom",
    # APT / nation-state tools
    "PlugX",
    "ShadowPad",
    "Winnti",
    "Flame",
    "Shamoon",
    "BlackEnergy",
    "GreyEnergy",
    "Industroyer",
    "Stuxnet",
    "Turla",
    "Snake",
    "ComRAT",
    "Duqu",
    "Gauss",
    "MiniFlame",
    "Regin",
    "ProjectSauron",
    "EternalBlue",
    "DoublePulsar",
    "WannaMine",
    # Post-exploitation / red team tools
    "Mimikatz",
    "BloodHound",
    "SharpHound",
    "Responder",
    "Impacket",
    "LaZagne",
    "Rubeus",
    "Certify",
    "Seatbelt",
    "PowerView",
    "PowerSploit",
    "Nmap",
    "Metasploit",
    "Burp Suite",
    "SQLMap",
    "Nikto",
}

# Ransomware group subset (active RaaS operators)
_RANSOMWARE_DICT: set[str] = {
    "LockBit", "LockBit 2.0", "LockBit 3.0",
    "BlackCat", "ALPHV",
    "Cl0p", "Clop",
    "REvil", "Sodinokibi",
    "Conti",
    "BlackMatter",
    "Hive",
    "Vice Society",
    "Play",
    "Royal",
    "Akira",
    "BlackSuit",
    "Avaddon",
    "DarkSide",
    "Maze",
    "Ryuk",
    "Egregor",
    "Babuk",
    "DoppelPaymer",
    "MedusaLocker",
    "Prometheus",
    "Grief",
    "Ragnar Locker",
    "RagnarLocker",
    "Cuba",
    "BlackBasta",
    "Black Basta",
    "Yanluowang",
    "Quantum",
    "Monti",
    "Nokoyawa",
    "Trigona",
    "Rhysida",
    "Hunters International",
    "Cactus",
    "INC Ransom",
    "KillSec",
    "Dispossessor",
    "Eldorado",
    "SenSayQ",
    "RansomHub",
    "DragonForce",
    "Scattered Spider",
    "Dark Angels",
    "8Base",
    "Qilin",
    "Fog",
    "Lynx",
    "Cicada3301",
    "Embargo",
    "Karakurt",
    "GandCrab",
    "SamSam",
    "WannaCry",
    "NotPetya",
    "Petya",
}

# ---------------------------------------------------------------------------
# Build compiled patterns from the dictionaries (at module load time)
# ---------------------------------------------------------------------------

def _build_pattern(names: set[str]) -> re.Pattern:
    """Build a word-bounded alternation pattern sorted longest-first."""
    sorted_names = sorted(names, key=len, reverse=True)
    alternation = "|".join(re.escape(name) for name in sorted_names)
    return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)


_MALWARE_RE = _build_pattern(_MALWARE_DICT)
_RANSOMWARE_RE = _build_pattern(_RANSOMWARE_DICT)

# ---------------------------------------------------------------------------
# Heuristic threat-actor handle detection
# Context patterns: "posted by X", "user X", "alias X", "known as X", etc.
# Handle: 3–30 chars, may contain underscores / dots / hyphens but not
#         starting or ending with them; must not be a plain email address.
# ---------------------------------------------------------------------------

_HANDLE_CHAR = r"[a-zA-Z0-9][a-zA-Z0-9_.\-]{1,28}[a-zA-Z0-9]"
_HANDLE_RE = re.compile(
    r"(?:"
    r"posted\s+by|user\s+|alias\s+|known\s+as|by\s+user"
    r"|from\s+user|handle\s+|nickname\s+|nick\s+"
    r"|op\s+is|author\s+|authored\s+by|written\s+by"
    r")\s*(" + _HANDLE_CHAR + r")",
    re.IGNORECASE,
)

# Threat-context gate for spaCy ORG extraction.  This is a *precision gate*
# (only look for victim/target orgs on pages that are actually about a breach or
# attack), NOT a denylist of entity strings — the accept/reject decision for
# each candidate is made structurally by extractor.entity_shape.
_THREAT_CONTEXT: frozenset[str] = frozenset({
    "breach", "leak", "attack", "ransom", "victim", "target",
    "compromised", "hacked", "stolen", "exfiltrated", "extorted",
    "encrypted", "infected", "malware", "ransomware", "exploit",
    "vulnerability", "phishing", "credentials", "data",
})

# ---------------------------------------------------------------------------
# spaCy singleton — loaded lazily on first call, never reloaded
# ---------------------------------------------------------------------------

_nlp = None
_nlp_attempted = False


def _get_nlp():
    global _nlp, _nlp_attempted
    if _nlp_attempted:
        return _nlp
    _nlp_attempted = True
    try:
        import spacy  # noqa: PLC0415
        _nlp = spacy.load("en_core_web_sm")
        logger.info("spaCy en_core_web_sm loaded successfully")
    except Exception as exc:
        logger.warning(
            "spaCy model en_core_web_sm is not available — NER will be skipped. "
            "Install with: python -m spacy download en_core_web_sm. Error: %s",
            exc,
        )
        _nlp = None
    return _nlp


def get_nlp():
    """Public accessor for the single cached ``en_core_web_sm`` spaCy pipeline.

    Returns the shared, lazily-loaded ``Language`` object, or ``None`` when the
    model is not installed. Exposed so other modules (e.g. the sanitizer's
    PERSON/GPE redaction) reuse the ONE loader rather than calling
    ``spacy.load`` a third time. A ``None`` return is a *distinguishable*
    unavailability signal — callers that must not silently skip redaction should
    treat it as fail-closed.
    """
    return _get_nlp()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def load_malware_dictionary() -> set[str]:
    """Return the full set of known malware family names used for matching."""
    return set(_MALWARE_DICT)


def extract_named_entities(text: str) -> dict[str, list[str]]:
    """
    Extract named entities that don't have fixed regex patterns.

    Returns a dict with the same format as regex_patterns.extract_all().
    If spaCy is unavailable, regex-based malware matching still runs;
    threat actor handles are extracted heuristically.
    Never raises.
    """
    result: dict[str, list[str]] = {
        THREAT_ACTOR_HANDLE: [],
        MALWARE_FAMILY: [],
        RANSOMWARE_GROUP: [],
        ORGANIZATION_NAME: [],
    }

    try:
        # --- Malware & ransomware: dictionary-based regex (no spaCy needed) ---
        result[MALWARE_FAMILY] = _dedup(
            m.group(0) for m in _MALWARE_RE.finditer(text)
        )
        result[RANSOMWARE_GROUP] = _dedup(
            m.group(0) for m in _RANSOMWARE_RE.finditer(text)
        )

        # --- Threat actor handles: heuristic context matching ---
        # The context regex proposes candidates; entity_shape decides acceptance
        # (entity shape or known-good gazetteer), replacing the old
        # common-word denylist so a never-before-seen generic word is rejected
        # structurally rather than only if someone had listed it.
        handles: list[str] = []
        for m in _HANDLE_RE.finditer(text):
            handle = m.group(1).strip()
            if "@" in handle:
                continue
            if _shape.evaluate(THREAT_ACTOR_HANDLE, handle).accept:
                handles.append(handle)
        result[THREAT_ACTOR_HANDLE] = _dedup(handles)

        # --- Organization names: spaCy ORG entities in threat context ---
        nlp = _get_nlp()
        if nlp is not None:
            text_lower = text.lower()
            has_threat_context = any(w in text_lower for w in _THREAT_CONTEXT)
            if not has_threat_context:
                # Short reports/README files may have no generic threat word,
                # but a gazetteer-confirmed actor can still be emitted by
                # spaCy as ORG (for example, ``Lazarus Group``). Inspect only
                # for known actor spans outside the broader organization gate.
                doc = nlp(text[:100_000])  # cap for performance
                for ent in doc.ents:
                    if ent.label_ != "ORG":
                        continue
                    candidate = ent.text.strip()
                    if gazetteer.category_of(candidate) == "threat_actor":
                        result[THREAT_ACTOR_HANDLE].append(candidate)
            if has_threat_context:
                doc = nlp(text[:100_000])  # cap for performance
                orgs: list[str] = []
                for ent in doc.ents:
                    if ent.label_ == "ORG":
                        candidate = ent.text.strip()
                        # A known actor can be returned by spaCy as an ORG when
                        # the surrounding generic qualifier is included in the
                        # span (for example, "LockBit Ransomware Group").
                        # Preserve the extracted value but emit the gazetteer
                        # classification so downstream normalization does not
                        # misfile it as ORGANIZATION_NAME.
                        category = gazetteer.category_of(candidate)
                        if category == "threat_actor":
                            result[THREAT_ACTOR_HANDLE].append(candidate)
                            continue
                        if category == "ransomware":
                            result[RANSOMWARE_GROUP].append(candidate)
                            continue
                        if category == "malware":
                            result[MALWARE_FAMILY].append(candidate)
                            continue
                        if should_suppress_organization(candidate, text):
                            continue
                        # Accept only if it has organisation shape (proper-noun
                        # structure, org suffix, brand casing) — not merely
                        # "absent from a denylist".
                        if _shape.evaluate(
                            ORGANIZATION_NAME, candidate, context_text=text
                        ).accept:
                            orgs.append(candidate)
                result[ORGANIZATION_NAME] = _dedup(orgs)
                result[THREAT_ACTOR_HANDLE] = _dedup(result[THREAT_ACTOR_HANDLE])
                result[MALWARE_FAMILY] = _dedup(result[MALWARE_FAMILY])
                result[RANSOMWARE_GROUP] = _dedup(result[RANSOMWARE_GROUP])

    except Exception:
        logger.exception("extract_named_entities encountered an unexpected error")

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dedup(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
