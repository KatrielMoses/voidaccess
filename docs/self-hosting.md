# Self-Hosting VoidAccess

VoidAccess can run as a local CLI or as a four-service Docker Compose stack with PostgreSQL, Tor, FastAPI, and the Next.js web interface.

## Requirements

- Docker Engine or Docker Desktop with Docker Compose
- Python 3 for setup-time secret generation
- An LLM provider key, or a local Ollama instance

## Guided setup

On macOS, Linux, or WSL:

```bash
git clone https://github.com/KatrielMoses/VoidAccess.git
cd VoidAccess
bash setup.sh
```

On native Windows:

```bat
git clone https://github.com/KatrielMoses/VoidAccess.git
cd VoidAccess
setup.bat
```

The setup wizard creates `.env`, generates `JWT_SECRET` and `POSTGRES_PASSWORD`, configures the selected LLM provider, collects optional enrichment keys, and starts the stack.

## Manual Docker Compose setup

```bash
git clone https://github.com/KatrielMoses/VoidAccess.git
cd VoidAccess
cp .env.example .env
docker compose up --build -d
```

Set at least `POSTGRES_PASSWORD`, `JWT_SECRET`, and one supported LLM provider key in `.env` before starting the stack. Keep `.env` private; it is ignored by Git.

| Service | URL or port | Purpose |
|---|---|---|
| Web UI | `http://localhost:3001` | Investigation dashboard |
| API | `http://localhost:8000` | REST API and `/docs` schema |
| PostgreSQL | `localhost:5433` | Persistent investigation data |
| Tor | `localhost:9050` | SOCKS5 access to `.onion` services |

## Operations

```bash
docker compose ps
docker compose logs -f
docker compose down
```

Convenience wrappers live in `scripts/`: `start.sh`, `stop.sh`, `start.bat`, and `stop.bat`. The health diagnostic is `scripts/check_health.sh`.

## Configuration

The checked-in [`.env.example`](../.env.example) documents all supported settings. Enrichment keys are optional and their integrations skip cleanly when unset.

The Docker build definitions and override example live in [`docker/`](../docker/). To customize local service settings, copy `docker/docker-compose.override.yml.example` to `docker-compose.override.yml` in the repository root.

## Data disclosure and first-run settings

An investigation contacts external sources. Search engines, code forges and paste
searches can receive your query. Hosted LLM providers receive the query and
collected page text. Enabled enrichment providers can receive discovered email
addresses, domains, IPs, hashes and wallets. Optional ScrapingAnt transport sees
the clearnet requests it handles; DeepL receives text submitted for translation.
Tor routing for onion pages does not route these separate clearnet services.

`VOIDACCESS_PRIVATE_MODE=true` is the default: shared-corpus reads, contributions
and configured snapshot uploads are disabled. It does not disable the requests
above or prevent local reports, page text and caches from being stored. Set it
to `false` only when you intend to participate in the configured corpus. Snapshot
uploads additionally require the operator's S3 endpoint, bucket and credentials.

The supplied `.env.example` selects `cisa_kev,nvd,mitre_attack` for enrichment.
These download public reference datasets rather than sending discovered email
addresses to breach services. `VOIDACCESS_ENRICHMENT_SOURCES` controls enrichment
only: unsetting it or leaving it blank enables every eligible enrichment source.
Use the IDs in `sources/enrichment_allowlist.py` to select additional services;
`VOIDACCESS_DISABLED_SOURCES` can also disable individual search or enrichment
sources using the IDs in `sources/source_control.py`.

For a first CLI experiment, use a public project name and disable Tor and LLM
processing. In PowerShell:

```powershell
$env:VOIDACCESS_PRIVATE_MODE = "true"
$env:VOIDACCESS_ENRICHMENT_SOURCES = "cisa_kev,nvd,mitre_attack"
voidaccess investigate "PUBLIC PROJECT NAME" --no-tor --no-llm --depth shallow
```

This still contacts clearnet search and feed providers. Do not enter passwords,
private documents or production credentials. Inspect the report's sources and
coverage: missing results or an unavailable service cannot establish that no
exposure exists. Treat inferred relationships and generated detection rules as
leads to verify before acting on them.

The CLI does not install the spaCy model during an investigation. Install it
explicitly during setup with `python -m spacy download en_core_web_sm` if named
entity recognition is needed; fixed-pattern extraction works without it.

## API authentication

The setup wizard creates the administrator account. Request a JWT with the configured credentials:

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@voidaccess.tech", "password": "yourpassword"}'
```

Pass the returned token as `Authorization: Bearer <token>` on protected API requests.

## Troubleshooting

- If services are slow on first boot, allow Tor and the initial image build several minutes, then run `docker compose ps`.
- Use `docker compose logs -f fastapi` for backend startup or migration failures.
- Check host ports `3001`, `8000`, `5433`, and `9050` for conflicts.
- If `.env` is missing, rerun `bash setup.sh` or `setup.bat`.
- The first image build is large; later builds reuse Docker's layer cache.

See [Architecture and technical reference](architecture.md) for the service topology, pipeline internals, schema, API surface, and configuration reference.


## Multi-user upgrade to 2.1.0

Follow [the October 2026 security advisory](SECURITY-ADVISORY-2026-10.md) before
sharing an installation. Run `alembic upgrade head`, then
`python -m scripts.migrate_multiuser` to import legacy YAML watches and backfill
Chroma owners to the first administrator. YAML is read-only input; monitor CRUD
uses the database. Use `voidaccess admin promote --email EMAIL` for role recovery.
Start Uvicorn with `--no-proxy-headers` and set `VOIDACCESS_TRUSTED_PROXIES` only
for controlled proxies. `VOIDACCESS_GLOBAL_RATE_LIMIT` and
`VOIDACCESS_USER_RATE_LIMIT` default to 120/minute each. See the advisory for
count/CIDR examples and migration attribution limitations.
