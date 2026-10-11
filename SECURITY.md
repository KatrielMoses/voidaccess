# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.7.x   | Yes       |


Only the latest release line receives security fixes.

## What Counts as a Vulnerability

This project connects to dark web sites via Tor, uses LLMs to process queries and content, and stores threat intelligence. A valid vulnerability is something that:

- Allows authentication bypass or privilege escalation between user accounts
- Exposes API keys or secrets stored for other users or the server
- Executes SSRF by bypassing the URL validation in the scraping layer
- Injects malicious prompts into LLM workflows via user input
- Grants access to data belonging to other users

The following are not in scope:

- Issues in third-party dark web search engines this project connects to
- Findings from automated scanners without a proof of concept
- Social engineering or phishing that targets users of this platform
- Theoretical attacks with no realistic exploitation path

## Reporting

Use GitHub private vulnerability reporting if available. If not, email katriel.moses@gmail.com.

Include in your report:

- Description of the issue
- Steps to reproduce
- Affected component (e.g., /auth/login endpoint, scrape.py)
- Potential impact
- Any suggested fix you have

### Response Timeline

- Acknowledge within 48 hours
- Status updates within 7 days
- Fix timeline communicated once confirmed

## What Happens After a Report

We investigate and confirm the issue. If valid, we fix it before public disclosure. We credit the reporter in release notes unless they prefer anonymity. We do not take legal action against good-faith researchers who follow this policy.

## Security Design

The API runs as a non-root user inside Docker containers (uid 1000, gid 1000). JWTs expire after 8 hours and include a unique ID (jti) that gets stored in Redis for revocation when users log out.

Token revocation behaviour on Redis availability is a deliberate design decision. If `REDIS_URL` is **not** configured, the blacklist is disabled by design and tokens remain valid until natural expiry (fail-open — for operators who choose not to run Redis). If `REDIS_URL` **is** configured but Redis becomes unreachable, revocation is treated as a required control and the API **fails closed**: authenticated requests are rejected with `503 Service Unavailable` and an operator warning is logged, rather than silently accepting possibly-revoked tokens. Enforcement resumes automatically once Redis recovers. This trades availability for revocation integrity when revocation has been explicitly opted in; unset `REDIS_URL` to prefer availability instead.

API keys provided by users are encrypted with Fernet (AES-128) using a key derived from JWT_SECRET. Server-level keys are stored in environment variables only.

Rate limiting is applied to auth endpoints (5/minute login, 3/minute password reset) and a global limit to all API routes (100/minute). These can be disabled via DISABLE_RATE_LIMIT=true.

The scraping layer validates every URL before fetch. It blocks internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, link-local, IPv6 private) and known internal hostnames. Onion addresses pass through because Tor handles the routing. This prevents accidental internal network exposure.

## Known Limitations

Tor circuit saturation can cause timeouts or failures under heavy scraping loads. The SSRF protection resolves hostnames once before the request, so short-TTL DNS rebinding is a theoretical risk that firewall-level egress policies would mitigate. This is considered an accepted risk given the tool's threat model focuses on passive OSINT collection rather than defended network targets.

Free-tier LLM providers impose rate limits that trigger retry logic, which could be observed in request patterns.
