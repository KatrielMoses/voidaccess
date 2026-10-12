"""Wheel packaging test: the built wheel must be self-sufficient.

Builds a wheel from a *copy* of the source tree (so the repo's stale ``build/``
and ``*.egg-info`` can neither pollute nor leak into the result), installs it
with its dependencies into a fresh venv outside the repo, and imports every
module shipped in the wheel from a cwd that does not contain the source tree.

Regression guard for: ``pip install voidaccess`` omitting runtime top-level
packages (shared_corpus, trust_gate, netpool, ...) because they were missing
from ``[tool.setuptools.packages.find] include``.

Run with:  pytest tests/test_packaging.py -m packaging
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.packaging

REPO = Path(__file__).resolve().parent.parent

# Modules we tolerate failing to import because they need optional heavy deps.
OPTIONAL_DEPS = {
    "chromadb", "sentence_transformers", "playwright", "telethon", "torch",
    "transformers",
}

BUILD_TIMEOUT = 600
INSTALL_TIMEOUT = 1800
IMPORT_TIMEOUT = 900

_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "build", "dist", "*.egg-info", "tests", "node_modules", "web",
    "__pycache__", "*.pyc", ".venv", "venv", "chroma_db", "cti_data", "docs",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
)

_IMPORT_SCRIPT = r"""
import importlib, json, sys
mods = json.loads(sys.argv[1])
own = set(json.loads(sys.argv[2]))
out = {"missing_own": [], "optional": [], "other": [], "ok": 0}
for m in mods:
    try:
        importlib.import_module(m)
        out["ok"] += 1
    except ModuleNotFoundError as e:
        top = (e.name or "").split(".")[0]
        if top in own:
            out["missing_own"].append(f"{m}: {e}")
        else:
            out["optional"].append(f"{m}: [{top}] {e}")
    except BaseException as e:  # noqa: BLE001 - report everything
        out["other"].append(f"{m}: {type(e).__name__}: {e}")
print("RESULT:" + json.dumps(out))
"""


def _run(cmd, cwd, timeout, env=None):
    return subprocess.run(
        [str(c) for c in cmd], cwd=str(cwd), capture_output=True, text=True,
        timeout=timeout, env=env,
    )


def _build_wheel(src: Path, outdir: Path) -> Path:
    attempts = [
        [sys.executable, "-m", "build", "--wheel", "--outdir", outdir, "."],
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", outdir],
    ]
    if shutil.which("uv"):
        attempts.append(["uv", "build", "--wheel", "--out-dir", outdir, "."])
    errors = []
    for cmd in attempts:
        r = _run(cmd, src, BUILD_TIMEOUT)
        wheels = sorted(outdir.glob("voidaccess-*.whl"))
        if r.returncode == 0 and wheels:
            return wheels[0]
        errors.append(f"$ {' '.join(map(str, cmd))}\n{(r.stdout + r.stderr)[-800:]}")
    pytest.fail("could not build wheel:\n" + "\n".join(errors))


def _wheel_modules(wheel: Path):
    """Return (top_level_names, importable_module_names) from the wheel."""
    tops, mods = set(), []
    with zipfile.ZipFile(wheel) as z:
        for name in z.namelist():
            if name.endswith("top_level.txt"):
                tops.update(z.read(name).decode().split())
                continue
            if ".dist-info/" in name or ".data/" in name or not name.endswith(".py"):
                continue
            parts = name[:-3].split("/")
            tops.add(parts[0])
            if parts[-1] == "__main__" or "migrations" in parts:
                continue
            if parts[-1] == "__init__":
                parts = parts[:-1]
            mods.append(".".join(parts))
    return sorted(tops), sorted(set(mods))


def test_wheel_installs_and_imports(tmp_path):
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("uv not on PATH; cannot create a fresh venv with dependencies quickly")

    src = tmp_path / "src"
    shutil.copytree(REPO, src, ignore=_COPY_IGNORE, symlinks=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _build_wheel(src, dist)

    tops, modules = _wheel_modules(wheel)
    # "Ours" = every top-level package/module in the source tree (not just what
    # made it into the wheel, otherwise a wholly-omitted package looks foreign).
    own = sorted(
        {p.name for p in src.iterdir() if p.is_dir() and (p / "__init__.py").exists()}
        | {p.stem for p in src.glob("*.py") if p.name != "setup.py"}
        | set(tops)
    )
    assert "voidaccess_cli" in tops, tops
    assert len(modules) > 50, f"suspiciously small wheel: {len(modules)} modules"

    venv = tmp_path / "venv"
    r = _run([uv, "venv", venv, "--python", sys.executable], tmp_path, 300)
    assert r.returncode == 0, r.stdout + r.stderr
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    vpy = bindir / ("python.exe" if os.name == "nt" else "python")

    r = _run([uv, "pip", "install", "--python", vpy, wheel], tmp_path, INSTALL_TIMEOUT)
    if r.returncode != 0:
        out = (r.stdout + r.stderr).lower()
        if any(k in out for k in ("network", "dns", "connect", "timed out", "resolve")):
            pytest.skip("network unavailable for dependency install: " + out[-300:])
        pytest.fail("wheel install failed:\n" + (r.stdout + r.stderr)[-2000:])

    # cwd is a clean dir without the source tree; isolate from any inherited path.
    cwd = tmp_path / "run"
    cwd.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "VIRTUAL_ENV")}
    env["PYTHONNOUSERSITE"] = "1"
    env["HOME"] = str(home)

    r = _run([vpy, "-I", "-c", _IMPORT_SCRIPT, json.dumps(modules), json.dumps(own)],
             cwd, IMPORT_TIMEOUT, env)
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("RESULT:")), None)
    assert line, f"import probe crashed (rc={r.returncode}):\n{(r.stdout + r.stderr)[-2000:]}"
    res = json.loads(line[len("RESULT:"):])

    tolerated = [x for x in res["optional"]
                 if x.split("[", 1)[1].split("]")[0] in OPTIONAL_DEPS]
    unexpected = [x for x in res["optional"] + res["other"] if x not in tolerated]
    print(f"imported ok: {res['ok']}/{len(modules)}; tolerated optional: {len(tolerated)}")
    for x in unexpected:
        print("NOTE (non-fatal) import problem:", x)

    # Every source top-level package must be shipped, except non-runtime ones.
    not_shipped = sorted(set(own) - set(tops) - {"tests", "setup", "conftest"})
    assert not not_shipped, f"top-level packages in source but not in wheel: {not_shipped}"

    assert not res["missing_own"], (
        "modules from our own packages are missing from the wheel:\n  "
        + "\n  ".join(res["missing_own"])
        + ("\nother import problems:\n  " + "\n  ".join(unexpected) if unexpected else "")
    )

    # Package-data the runtime reads must ship too.
    with zipfile.ZipFile(wheel) as z:
        names = set(z.namelist())
    for required in ("benchmark/data/benchmark_queries.json",
                     "sources/data/onion_seeds.json",
                     "data/threat_gazetteer.json",
                     # E1C: the cancel helper and the source deny-list/status module
                     # are imported by the CLI pipeline, so the wheel must carry them.
                     "utils/cancel.py",
                     "sources/source_control.py",
                     "voidaccess/summary_fallback.py"):
        assert required in names, f"{required} missing from wheel"

    for args in (["--help"], ["version"], ["investigate", "--help"]):
        r = _run([bindir / "voidaccess", *args], cwd, 300, env)
        assert r.returncode == 0, f"voidaccess {' '.join(args)} failed:\n{(r.stdout + r.stderr)[-1500:]}"
    assert "quiet" in r.stdout.lower()  # `investigate --help` lists the flag

    # The pipeline modules the CLI imports lazily resolve from the wheel alone.
    r = _run([vpy, "-I", "-c",
              "from utils import cancel; from sources import source_control as s; "
              "from voidaccess.llm import SummaryUnavailable; "
              "from voidaccess.summary_fallback import summarize_with_fallback; "
              "print(len(s.all_source_ids()))"], cwd, 300, env)
    assert r.returncode == 0, (r.stdout + r.stderr)[-1500:]
