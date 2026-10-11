import re


def defang_url(url: str) -> str:
    """
    Defang a URL for safe sharing in reports.
    hxxp://example[.]com/path
    """
    if not url:
        return url
    url = url.replace("http://", "hxxp://")
    url = url.replace("https://", "hxxps://")
    url = url.replace("ftp://", "fxp://")
    parts = url.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        url = "/".join(parts)
    else:
        url = url.replace(".", "[.]")
    return url


def defang_ip(ip: str) -> str:
    """
    Defang an IP address.
    1.2.3.4 -> 1.2.3[.]4
    """
    if not ip:
        return ip
    parts = ip.rsplit(".", 1)
    if len(parts) == 2:
        return f"{parts[0]}[.]{parts[1]}"
    return ip


def defang_ipv6(ip: str) -> str:
    """
    Defang an IPv6 address so it is not clickable/resolvable.
    2001:db8::1 -> 2001[:]db8[:][:]1
    """
    if not ip:
        return ip
    return ip.replace(":", "[:]")


def defang_email(email: str) -> str:
    """
    Defang an email address.
    user@example.com -> user[@]example[.]com
    """
    if not email:
        return email
    email = email.replace("@", "[@]")
    parts = email.split("[@]", 1)
    if len(parts) == 2:
        parts[1] = parts[1].replace(".", "[.]")
        email = "[@]".join(parts)
    return email


# Entity types that carry a resolvable/clickable network address and MUST be
# routed through ``defang_url`` for display. Kept as the single audited coverage
# set so no network-IOC type can silently fall through to the identity branch
# and be shown raw under a ``defanged:true`` label.
#
#   URL / PASTE_URL — generic + paste-site clearnet URLs (INT-F4: were falling
#     through to identity, shown raw).
#   ONION_URL       — dark-web URLs.
#   DOMAIN / DOMAIN_NAME — bare hostnames (both spellings are emitted; see
#     ``extractor/pipeline.py`` and ``extractor/normalizer.py``).
#   ENS_DOMAIN      — resolvable ``.eth``-style names (folded in per the audit).
_URL_DEFANG_TYPES = frozenset({
    "URL",
    "PASTE_URL",
    "ONION_URL",
    "DOMAIN",
    "DOMAIN_NAME",
    "ENS_DOMAIN",
})


def defang_value(entity_type: str, value: str) -> str:
    """
    Defang an entity value based on its type.
    Returns the defanged version for display. This is the single dispatch
    authority: ``hygiene.defang_ioc`` and both API entity surfaces route through
    it, so coverage added here is coverage everywhere.
    """
    if entity_type in _URL_DEFANG_TYPES:
        return defang_url(value)
    elif entity_type == "IP_ADDRESS":
        return defang_ip(value)
    elif entity_type == "IPV6_ADDRESS":
        return defang_ipv6(value)
    elif entity_type == "EMAIL_ADDRESS":
        return defang_email(value)
    else:
        return value


def defang_value_checked(entity_type: str, value: str) -> tuple[str, bool]:
    """
    Defang ``value`` and report whether it was actually transformed.

    Returns ``(defanged_value, changed)`` where ``changed`` is ``True`` iff the
    defanged form differs from the input. This is the single source of truth for
    the API ``defanged`` flag: deriving the flag from a real transform makes it
    structurally impossible to report ``defanged:true`` for a value that was
    left untouched (INT-F4 flag honesty).
    """
    if not value:
        return value, False
    defanged = defang_value(entity_type, value)
    return defanged, defanged != value


def defang_text(text: str) -> str:
    """
    Defang all URLs and IPs found in free text.
    Use for report summaries and context snippets.
    """
    if not text:
        return text

    text = re.sub(
        r'https?://',
        lambda m: m.group().replace(
            "http://", "hxxp://"
        ).replace(
            "https://", "hxxps://"
        ),
        text
    )

    text = re.sub(
        r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})'
        r'\.(\d{1,3})\b',
        r'\1.\2.\3[.]\4',
        text,
    )

    return text