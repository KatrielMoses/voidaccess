# Deploying VoidAccess on one always-free box (no Redis)

VoidAccess's central service is designed to run end-to-end on a **single
always-on box, with no Redis and no message broker** (P2.3). Background work
(investigation dispatch, and later crawl/freshness + ingest) runs on the
DB-backed durable job queue; rate limiting is in-process; token revocation is
DB-backed. That means the whole stack fits the free tier of a small cloud VM and
migrates to a paid VPS with one command — no provider lock-in.

- **No Redis.** The `docker-compose.yml` stack is four services —
  `postgres`, `tor`, `fastapi`, `nextjs`. There is no `redis` service and none is
  required. `REDIS_URL` is optional; leave it unset.
- **SQLite or Postgres.** The default stack uses Postgres; a single-box $0 mode
  can drop Postgres and run the API on a SQLite file (see below).
- **Durable across restarts.** An investigation in flight when the box reboots
  is resumed/re-queued by a worker — not lost.

---

## Option A — Oracle Cloud Always Free (recommended $0 path)

Oracle's Always Free tier includes **Ampere A1 (ARM)** instances (up to 4 OCPU /
24 GB RAM) that never expire — enough to run the full stack. VoidAccess's images
are multi-arch, so ARM works.

### 1. Create the instance

1. Oracle Cloud Console → **Compute → Instances → Create**.
2. Shape: **VM.Standard.A1.Flex** (Always Free eligible). 2 OCPU / 12 GB is
   plenty; 4/24 if available.
3. Image: **Ubuntu 22.04 (aarch64)**.
4. Add your SSH public key. Create.
5. **Networking → Virtual Cloud Network → Security List → Ingress Rules**: allow
   TCP **3001** (web) and **8000** (API) from your IP (or `0.0.0.0/0` if you
   front it with a reverse proxy + TLS — recommended). Leave Postgres (5433) and
   Tor (9050) closed to the internet.

### 2. Install Docker

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git
sudo usermod -aG docker "$USER" && newgrp docker
# Oracle Ubuntu images default to a restrictive iptables policy — open the two ports:
sudo iptables -I INPUT -p tcp --dport 3001 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
sudo netfilter-persistent save
```

### 3. Deploy

```bash
git clone https://github.com/KatrielMoses/VoidAccess.git
cd VoidAccess/voidaccess
cp .env.example .env
# Edit .env: set JWT_SECRET (python -c "import secrets;print(secrets.token_hex(32))"),
# POSTGRES_PASSWORD, and any API keys you want. Leave REDIS_URL unset.
docker compose up --build -d
```

Migrations run automatically at API startup (`alembic upgrade head` in the
entrypoint). Check health:

```bash
docker compose ps
curl -fsS http://localhost:8000/health
```

Web UI: `http://<instance-ip>:3001`, API: `http://<instance-ip>:8000`.

> **TLS:** for anything public, put Caddy or nginx in front of `:3001`/`:8000`
> and terminate HTTPS there. The rate limiter reads `X-Forwarded-For`, so a
> reverse proxy's per-client limits work correctly.

### Single-box $0 mode without Postgres (SQLite)

To shed the Postgres container entirely and run on a SQLite file (lowest
footprint), point the API at a SQLite DB and don't start `postgres`:

```bash
# in .env
DATABASE_URL=sqlite:////app/data/voidaccess.db
```

```bash
docker compose up -d --build fastapi nextjs tor   # no postgres service
```

The `monitors_data` volume already mounts `/app/data`, so the SQLite file
persists across restarts. Everything (queue, auth, revocation) works on SQLite —
the durable queue's atomic claim has a SQLite-compatible strategy.

---

## Option B — one-command migration to a paid VPS (fallback, no lock-in)

If you outgrow the free tier (or Oracle reclaims capacity), move to any VPS
(Hetzner, DigitalOcean, a spare box) with **one command**. `scripts/migrate-to-vps.sh`
bundles the state that isn't in git — your `.env` and the data volumes
(Postgres data or the SQLite file, Chroma vectors, monitors/seeds, Tor keys) —
ships it over SSH, and brings the stack up on the target:

```bash
# From the current host, inside voidaccess/:
scripts/migrate-to-vps.sh user@new-vps-host
```

It performs, in order: `docker compose stop` (quiesce), a tarball of `.env` +
named volumes, `rsync` of the repo + bundle to the target, restore, and
`docker compose up -d --build` on the target. Because state travels with it, the
new box comes up with your users, investigations, shared corpus, and **any queued
jobs intact** — a reboot/migration resumes in-flight work rather than dropping
it. Nothing is Oracle-specific; the same command targets any Docker host.

See the script header for prerequisites (SSH access, Docker on the target) and
flags (`--sqlite` when running the Postgres-less mode).

---

## Operating notes

- **Workers:** the API process runs the queue worker(s) in its lifespan.
  `VOIDACCESS_QUEUE_WORKERS` sets the count (default 1);
  `VOIDACCESS_DISABLE_QUEUE_WORKER=true` runs the API as an enqueue-only front
  end (useful if you later split workers onto their own container — they share
  the same DB, no broker).
- **Rate limits:** `VOIDACCESS_GLOBAL_RATE_LIMIT` (per-IP/min, default 120);
  `DISABLE_RATE_LIMIT=true` turns enforcement off.
- **Revocation:** with only `DATABASE_URL` set, logout revokes via the
  `revoked_tokens` table — no Redis. Set `REDIS_URL` only if you specifically
  want a Redis-backed blacklist.
- **Backups:** `docker compose exec postgres pg_dump -U voidaccess voidaccess`
  (Postgres mode) or copy the SQLite file from the `monitors_data` volume.
