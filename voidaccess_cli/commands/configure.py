"""
cli/commands/configure.py — first-run wizard and config sub-commands.

    voidaccess configure         — full wizard
    voidaccess configure llm     — just the LLM provider/key
    voidaccess configure keys    — just enrichment API keys
    voidaccess configure tor     — override Tor proxy host/port
    voidaccess configure proxy   — ScrapingAnt key + enable/disable toggle
"""

from __future__ import annotations

import sys
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from voidaccess_cli import config as cli_config


def _is_interactive() -> bool:
    """Return True if stdin is a TTY (interactive terminal)."""
    try:
        return sys.stdin.isatty()
    except Exception:
        return False

app = typer.Typer(help="Configure the voidaccess CLI.", no_args_is_help=False, invoke_without_command=True)
console = Console()


# Keys in ENRICHMENT_KEYS that get their own dedicated wizard step
# (with custom explanation) rather than the generic one-line prompt.
# Adding a key here means the generic iteration in _prompt_enrichment
# will skip it.  Phase 1.6: ScrapingAnt — the API key (the only real
# credential per https://docs.scrapingant.com/proxy-mode) gets a
# dedicated step with honest explanation; the proxy type also lives
# here so the entire proxy config lives in one uninterrupted block.
KEYS_WITH_DEDICATED_STEP = {
    "SCRAPINGANT_API_KEY",
    "SCRAPINGANT_PROXY_USERNAME",
    "SCRAPINGANT_PROXY_PASSWORD",
    "SCRAPINGANT_PROXY_TYPE",
}


PROVIDERS = [
    ("openrouter", "OpenRouter (free models available)"),
    ("groq",       "Groq (hosted inference)"),
    ("google",     "Google Gemini (free tier)"),
    ("openai",     "OpenAI (paid)"),
    ("anthropic",  "Anthropic (paid)"),
    ("ollama",     "Ollama (local, free)"),
]

DEFAULT_MODELS = {
    "openrouter": "openrouter/deepseek/deepseek-v4.1-flash",
    "groq":       "groq/openai/gpt-oss-120b",
    "google":     "gemini-3.8-flash",
    "openai":     "gpt-6-luna",
    "anthropic":  "claude-haiku-5-5",
    "ollama":     "ollama/gemma4",
}


def _print_provider_table() -> None:
    table = Table(title="LLM provider")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Provider", style="bold")
    table.add_column("Notes")
    for idx, (key, desc) in enumerate(PROVIDERS, start=1):
        suffix = " ← default" if key == "openrouter" else ""
        table.add_row(str(idx), key, desc + suffix)
    console.print(table)


def _test_llm_key(provider: str, api_key: str, model: str) -> bool:
    """Light credential validation — instantiate the LangChain class only."""
    if provider == "ollama":
        return True
    try:
        from voidaccess.llm import get_llm
    except ImportError as exc:
        missing = str(exc).split("'")[-2] if "'" in str(exc) else str(exc)
        console.print(
            f"[yellow]Skipped validation:[/yellow] missing dependency [bold]{missing}[/bold]. "
            f"Install with: [bold]pip install {missing.replace('_', '-')}[/bold]"
        )
        return False
    try:
        get_llm(model, api_keys={cli_config.PROVIDER_ENV.get(provider, ""): api_key})
        return True
    except ImportError as exc:
        missing = str(exc).split("'")[-2] if "'" in str(exc) else str(exc)
        console.print(
            f"[yellow]Skipped validation:[/yellow] missing dependency [bold]{missing}[/bold]. "
            f"Install with: [bold]pip install {missing.replace('_', '-')}[/bold]"
        )
        return False
    except Exception as exc:
        console.print(f"[yellow]Could not validate key:[/yellow] {exc}")
        return False


def _prompt_llm(cfg: dict) -> None:
    _print_provider_table()
    while True:
        choice = Prompt.ask(
            "Pick provider [1-6]",
            default="1",
            choices=[str(i) for i in range(1, len(PROVIDERS) + 1)],
            show_choices=False,
        )
        provider, _ = PROVIDERS[int(choice) - 1]
        break

    model = Prompt.ask(
        "Model identifier",
        default=DEFAULT_MODELS.get(provider, ""),
    )

    api_key = ""
    if provider != "ollama":
        api_key = Prompt.ask(
            f"API key for {provider}",
            default=cfg["llm"].get("api_key", "") if cfg["llm"].get("provider") == provider else "",
            password=True,
        )

    cfg["llm"]["provider"] = provider
    cfg["llm"]["model"] = model
    cfg["llm"]["api_key"] = api_key

    if api_key and provider != "ollama":
        console.print("Testing key…", style="grey50")
        if _test_llm_key(provider, api_key, model):
            console.print("[green]Key looks valid.[/green]")
        else:
            console.print("[yellow]Saved anyway — verify later with `voidaccess status`.[/yellow]")


def _prompt_enrichment(cfg: dict) -> None:
    console.print("\n[bold]Enrichment API keys[/bold] (press Enter to skip any)")
    for key_name in cli_config.ENRICHMENT_KEYS:
        # Phase 1.6 — keys with their own dedicated wizard step
        # (custom explanation + associated toggle) are handled by their
        # own _prompt_* function, not the generic one-liner.
        if key_name in KEYS_WITH_DEDICATED_STEP:
            continue
        existing = cfg["enrichment_keys"].get(key_name, "")
        display_default = "(saved)" if existing else "(skip)"
        val = Prompt.ask(f"  {key_name}", default=existing or "", show_default=False)
        cfg["enrichment_keys"][key_name] = val.strip()


def _prompt_scrapingant(cfg: dict) -> None:
    """Phase 1.6 — dedicated wizard step for the optional clearnet proxy.

    Honest, specific wording: this is opt-in, it affects paste sites and
    RSS feeds ONLY, and it never touches Tor/.onion traffic.

    SCRAPINGANT_API_KEY is exclusively the REST Web Scraping API credential.
    Proxy transport uses the separate dashboard-issued
    SCRAPINGANT_PROXY_USERNAME + SCRAPINGANT_PROXY_PASSWORD pair. The proxy
    username string is built at connection time with browser=false and
    proxy_type parameters.
    SCRAPINGANT_PROXY_TYPE selects residential vs datacenter as a
    username parameter, NOT as a different hostname.

    The two transport toggles (API / Proxy) are mutually exclusive
    alternates per the docs (proxy transport is "a light front-end for the
    scraping API"); we ask about each separately but they cannot be
    combined.
    """
    console.print("\n[bold]Clearnet proxy (ScrapingAnt)[/bold] — optional")
    console.print(
        "  Routes [cyan]clearnet scraping only[/cyan] — paste sites (Pastebin, "
        "dpaste, Rentry) and RSS feeds (Krebs, BleepingComputer, Talos, etc.) "
        "through ScrapingAnt's Web Scraping API or proxy transport to improve reliability."
    )
    console.print(
        "  [yellow]Never touches Tor traffic.[/yellow] Dark web and .onion fetches "
        "are unaffected regardless of this setting."
    )
    console.print(
        "  Sign up at [link=https://scrapingant.com/?ref=mzliyzh]"
        "[cyan]https://scrapingant.com/?ref=mzliyzh[/cyan][/link]"
        " (referral bonus applied on first paid plan — also unlocks"
        " a free tier for low-volume use)."
    )
    console.print("  Press Enter to skip any field.\n")

    # --- SCRAPINGANT_API_KEY (REST Web Scraping API transport only) ---
    existing_key = cfg["enrichment_keys"].get("SCRAPINGANT_API_KEY", "")
    prompt_default = existing_key or ""
    new_key = Prompt.ask(
        "  SCRAPINGANT_API_KEY",
        default=prompt_default,
        show_default=False,
        password=True,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = new_key.strip()

    console.print(
        "  [dim]Residential proxies use a separate username/password pair from the ScrapingAnt dashboard.[/dim]"
    )
    existing_username = cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_USERNAME", "")
    new_username = Prompt.ask(
        "  SCRAPINGANT_PROXY_USERNAME",
        default=existing_username or "",
        show_default=False,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_USERNAME"] = new_username.strip()

    existing_password = cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_PASSWORD", "")
    new_password = Prompt.ask(
        "  SCRAPINGANT_PROXY_PASSWORD",
        default=existing_password or "",
        show_default=False,
        password=True,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_PASSWORD"] = new_password.strip()

    # --- SCRAPINGANT_PROXY_TYPE (residential default; datacenter for higher bandwidth) ---
    # Per docs, this is passed as `proxy_type=` in the proxy transport
    # username string.  Only meaningful when the proxy transport
    # is selected; ignored otherwise.
    existing_type = (
        cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_TYPE", "") or "residential"
    ).strip().lower()
    if existing_type not in ("residential", "datacenter"):
        existing_type = "residential"
    console.print(
        "  [dim]Proxy pool type:[/dim] [cyan]residential[/cyan] (default — "
        "harder to detect, slightly higher latency) or [cyan]datacenter[/cyan] "
        "(faster, cheaper, easier to fingerprint).  Press Enter for residential."
    )
    type_choices = ["residential", "datacenter"]
    new_type = Prompt.ask(
        "  SCRAPINGANT_PROXY_TYPE",
        choices=type_choices,
        default=existing_type,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_TYPE"] = new_type.strip()

    # Transport selection — mutually exclusive alternates per docs.
    # We ask about each separately but they are NOT combinable: enabling
    # both means the chokepoint picks proxy (logged at runtime with a
    # one-shot info message).
    if new_key.strip():
        current_api = bool(cfg.get("features", {}).get("rest_api_transport_enabled", cfg.get("features", {}).get("use_proxies", False)))
        if Confirm.ask(
            "  Enable REST API transport (ScrapingAnt Web Scraping API) for clearnet scrapes?",
            default=current_api,
        ):
            cfg.setdefault("features", {})["rest_api_transport_enabled"] = True
            cfg.setdefault("features", {})["use_proxies"] = True
        else:
            cfg.setdefault("features", {})["rest_api_transport_enabled"] = False
            cfg.setdefault("features", {})["use_proxies"] = False

        current_proxy = bool(cfg.get("features", {}).get("residential_proxy_enabled", cfg.get("features", {}).get("use_proxy", False)))
        if Confirm.ask(
            f"  Enable proxy transport (HTTP CONNECT through the configured ScrapingAnt proxy endpoint, "
            f"{new_type} pool) for clearnet scrapes?",
            default=current_proxy,
        ):
            cfg.setdefault("features", {})["residential_proxy_enabled"] = True
            cfg.setdefault("features", {})["use_proxy"] = True
        else:
            cfg.setdefault("features", {})["residential_proxy_enabled"] = False
            cfg.setdefault("features", {})["use_proxy"] = False


def _prompt_output_dir(cfg: dict) -> None:
    current = cfg.get("output_dir") or str(cli_config.DEFAULT_OUTPUT_DIR)
    new_dir = Prompt.ask("Output directory", default=current)
    cfg["output_dir"] = new_dir


def _ensure_spacy_model() -> None:
    cli_config.ensure_spacy_model()


@app.callback()
def configure_default(ctx: typer.Context) -> None:
    """Run the full wizard when no sub-command is given."""
    if ctx.invoked_subcommand is not None:
        return
    # v1.7 MED-6: detect non-TTY stdin (piped / scripted invocation).
    # Abort with a clear message rather than silently accepting defaults
    # at every prompt, which produces an unexpected config silently.
    if not _is_interactive():
        console.print(
            "[yellow]voidaccess configure requires an interactive terminal.[/yellow]"
        )
        console.print(
            "Use non-interactive sub-commands instead:\n"
            "  voidaccess configure llm\n"
            "  voidaccess configure keys\n"
            "  voidaccess configure tor --host <host> --port <port>\n"
            "  voidaccess configure proxy\n"
        )
        raise typer.Exit(code=1)
    cfg = cli_config.load_config()
    console.print("[bold magenta]voidaccess — initial setup[/bold magenta]\n")
    _prompt_llm(cfg)
    if Confirm.ask("\nAdd enrichment API keys now?", default=False):
        _prompt_enrichment(cfg)
        # Phase 1.6 — dedicated step for keys that have associated
        # on/off behavior (currently just ScrapingAnt).  This sits
        # inside the "Add enrichment API keys now?" branch because
        # ScrapingAnt is functionally an optional key, but it gets
        # its own honest explanation rather than the generic one-liner.
        _prompt_scrapingant(cfg)
    _prompt_output_dir(cfg)
    cli_config.save_config(cfg)
    console.print(f"\n[green]Saved to[/green] {cli_config.CONFIG_PATH}")
    _ensure_spacy_model()


@app.command("llm")
def configure_llm() -> None:
    """Configure just the LLM provider, model, and API key."""
    cfg = cli_config.load_config()
    _prompt_llm(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")


@app.command("keys")
def configure_keys() -> None:
    """Configure enrichment API keys."""
    cfg = cli_config.load_config()
    _prompt_enrichment(cfg)
    # Phase 1.6 — ScrapingAnt also has its own dedicated prompt here
    # so users running `voidaccess configure keys` get the same honest
    # explanation they would in the full wizard.
    _prompt_scrapingant(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")


@app.command("tor")
def configure_tor(
    host: str = typer.Option("127.0.0.1", help="Tor SOCKS5 host"),
    port: int = typer.Option(9050, help="Tor SOCKS5 port"),
) -> None:
    """Override Tor proxy host/port."""
    cfg = cli_config.load_config()
    cfg["tor"]["host"] = host
    cfg["tor"]["port"] = port
    cli_config.save_config(cfg)
    console.print(f"Tor set to {host}:{port}")


@app.command("pace")
def configure_pace(
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help=f"Set the default pacing profile: {' | '.join(cli_config.PACE_PROFILES)}.",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Print the current pacing profile and what it does, then exit.",
    ),
) -> None:
    """Set the persistent default pacing profile.

    The pacing profile governs how patient and polite VoidAccess is with every
    scraped target — Tor, clearnet fetches, search engines, the individual
    source scrapers, and the Playwright JS renderer — through one shared
    setting instead of per-subsystem constants.

    \b
      quiet       long timeouts, long gaps between retries, fewer retries,
                  much longer politeness delays between requests
      normal      the baseline (default)
      aggressive  short timeouts, fast retries, minimal politeness delay

    This value persists across runs.  `voidaccess investigate --pace ...`
    overrides it for a single invocation without touching this config.
    """
    import pacing

    cfg = cli_config.load_config()
    current = cli_config.normalize_pace(cfg.get("pace", cli_config.DEFAULT_PACE))

    if profile is None or show:
        console.print("  [bold]Pacing profile[/bold]")
        for name in cli_config.PACE_PROFILES:
            marker = "[green]→[/green]" if name == current else " "
            console.print(f"  {marker} {pacing.describe(name)}")
        console.print(
            "\n  Override for one run with "
            "[bold]voidaccess investigate ... --pace <profile>[/bold]."
        )
        return

    candidate = profile.strip().lower()
    if candidate not in cli_config.PACE_PROFILES:
        console.print(
            f"[red]Invalid pace:[/red] {profile}. "
            f"Choose one of: {', '.join(cli_config.PACE_PROFILES)}."
        )
        raise typer.Exit(code=2)

    cfg["pace"] = candidate
    cli_config.save_config(cfg)
    console.print(f"Default pacing profile set to [green]{candidate}[/green]")
    console.print(f"  {pacing.describe(candidate)}")


@app.command("proxy")
def configure_proxy(
    enable: Optional[bool] = typer.Option(
        None,
        "--enable/--disable",
        help="Enable or disable the REST API transport (legacy pre-1.6.2 toggle).",
    ),
    enable_proxy: Optional[bool] = typer.Option(
        None,
        "--enable-proxy/--disable-proxy",
        help="Enable or disable the proxy transport (HTTP CONNECT through the configured ScrapingAnt proxy endpoint).",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Print current proxy config (key masked, pool type, both transport states) and exit.",
    ),
) -> None:
    """Configure the optional clearnet proxy (ScrapingAnt).

    With no flags, runs the interactive prompt.  With --enable / --disable,
    sets the REST API transport toggle non-interactively (legacy pre-1.6.2
    flag).  With --enable-proxy / --disable-proxy, sets the proxy transport
    transport toggle (new in v1.6.2 — requires the separate proxy
    username/password pair to actually activate).

    The two transports are MUTUALLY EXCLUSIVE alternates per
    https://docs.scrapingant.com/proxy-mode §Introduction ("proxy transport
    is a light front-end for the scraping API"). Setting one does not
    enable the other; if both are set, the chokepoint picks proxy transport
    and emits a one-shot info log.

    Clearnet scraping only — Tor and .onion traffic are never affected.
    """
    cfg = cli_config.load_config()
    # --show: display current state with the key masked, and exit.
    if show and enable is None and enable_proxy is None:
        key = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY", "")
        proxy_username = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_USERNAME", "")
        proxy_password = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_PASSWORD", "")
        proxy_type = (
            cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_TYPE", "") or "—"
        )
        api_transport = bool(cfg.get("features", {}).get("rest_api_transport_enabled", cfg.get("features", {}).get("use_proxies", False)))
        proxy_transport = bool(cfg.get("features", {}).get("residential_proxy_enabled", cfg.get("features", {}).get("use_proxy", False)))

        masked_key = (
            f"{key[:4]}…{key[-4:]}" if len(key) > 8 else ("set" if key else "—")
        )

        console.print("  [bold]ScrapingAnt proxy[/bold]")
        console.print(f"  Key             : {masked_key}")
        masked_username = (
            f"{proxy_username[:4]}…{proxy_username[-4:]}" if len(proxy_username) > 8 else ("set" if proxy_username else "—")
        )
        console.print(f"  Proxy username  : {masked_username}")
        console.print(f"  Proxy password  : {'set' if proxy_password else '—'}")
        console.print(f"  Pool type       : {proxy_type}")
        api_label = "[green]enabled[/green]" if api_transport else "[red]disabled[/red]"
        proxy_label = "[green]enabled[/green]" if proxy_transport else "[red]disabled[/red]"
        console.print(f"  REST API transport      : {api_label}")
        console.print(f"  Proxy transport         : {proxy_label}")
        console.print("  Scope           : paste + RSS only, never Tor")
        if proxy_transport and (not proxy_username or not proxy_password):
            console.print(
                "  [yellow]Note:[/yellow] proxy transport is enabled but the residential proxy username/password pair is incomplete — proxy transport will stay inactive until both values are provided."
            )
        if api_transport and not key:
            console.print(
                "  [yellow]Note:[/yellow] the REST API transport is enabled but no SCRAPINGANT_API_KEY is set yet."
            )
        if api_transport and proxy_transport:
            console.print(
                "  [yellow]Note:[/yellow] both transports are enabled. They are mutually "
                "exclusive alternates; the chokepoint picks proxy transport at runtime."
            )
        return

    if enable is not None:
        cfg.setdefault("features", {})["rest_api_transport_enabled"] = bool(enable)
        cfg.setdefault("features", {})["use_proxies"] = bool(enable)
        cli_config.save_config(cfg)
        state = "enabled" if enable else "disabled"
        console.print(f"ScrapingAnt REST API transport [green]{state}[/green]")
        if enable and not cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY"):
            console.print(
                "[yellow]Note:[/yellow] no SCRAPINGANT_API_KEY configured yet — "
                "set one with `voidaccess configure proxy` (interactive) or "
                "`voidaccess configure keys`."
            )
        return

    if enable_proxy is not None:
        cfg.setdefault("features", {})["residential_proxy_enabled"] = bool(enable_proxy)
        cfg.setdefault("features", {})["use_proxy"] = bool(enable_proxy)
        cli_config.save_config(cfg)
        state = "enabled" if enable_proxy else "disabled"
        console.print(f"ScrapingAnt proxy transport [green]{state}[/green]")
        if enable_proxy and not cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY"):
            console.print(
                "[yellow]Note:[/yellow] no SCRAPINGANT_API_KEY configured yet — "
                "set one with `voidaccess configure proxy` (interactive) or "
                "`voidaccess configure keys`."
            )
        return

    # No flags — run the interactive prompt
    _prompt_scrapingant(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")
