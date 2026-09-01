# CLI конвейера open-world-filter.
# Команды:
#   collect    скачать источники                        -> out/raw-entries.jsonl
#   classify   применить исключения и эвристики          -> out/entries.jsonl
#   build      collect + classify одним заходом
#   probe      пробы доступности (DNS/NS, опц. HTTPS)    -> out/probe-cache.json
#   resolve    IP-инвентарь: кэш проб + IP-источники     -> out/ips-all.lst (+ asn-map.json)
#   summarize  IP -> CIDR (с учётом ASN)                 -> out/ipsum.lst
#   emit       итоговые списки + forge.toml для мастерской
#   all        build -> probe -> resolve -> summarize -> emit
#   добавить   добавить домен/IP/CIDR в community/additions.txt (правка -> PR)
# Флаги (до или после команды): --root, --config, --output, --offline, --strict, --verbose.
# Коды выхода: 0 ok, 1 предупреждения источников при --strict, 2 ошибка конфигурации.

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from . import __version__
from .classify import apply_exclusions, flag_heuristics
from .collect import collect_source, sanitize_line
from .config import load_sources
from .provenance import Entry, load_entries, save_entries

EXIT_OK = 0
EXIT_SOURCE_WARNINGS = 1
EXIT_CONFIG_ERROR = 2

DEFAULT_OWNER = "acc-holo-dev"
DEFAULT_REPO = "open-world-filter"

# Общие флаги: доступны и до, и после подкоманды (в подпарсерах default=SUPPRESS,
# чтобы значение из подпарсера не перетирало значение, заданное до команды).
_COMMON_FLAGS = [
    (["--root"], {"type": Path, "default": None, "help": "корень проекта (по умолчанию cwd)"}),
    (["--config"], {"type": Path, "default": None, "help": "путь к sources.toml"}),
    (["--output"], {"type": Path, "default": None, "help": "директория результатов (по умолчанию <root>/out)"}),
    (["--offline"], {"action": "store_true", "default": False, "help": "пропускать удалённые источники"}),
    (["--strict"], {"action": "store_true", "default": False, "help": "предупреждения источников -> код выхода 1"}),
    (["--verbose"], {"action": "store_true", "default": False, "help": "детальный вывод"}),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="open-world-filter",
        description="Прозрачный конвейер списков блокировок (РКН + недоступное из РФ).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    for names, kw in _COMMON_FLAGS:
        parser.add_argument(*names, **kw)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(subp: argparse.ArgumentParser) -> None:
        for names, kw in _COMMON_FLAGS:
            subp.add_argument(*names, **{**kw, "default": argparse.SUPPRESS})

    for name, help_text in (
        ("collect", "скачать источники"),
        ("classify", "применить исключения к raw-entries.jsonl"),
        ("build", "collect + classify одним заходом"),
    ):
        add_common(sub.add_parser(name, help=help_text))

    all_p = sub.add_parser("all", help="полный конвейер (прозрачно: см. выше)")
    all_p.add_argument("--limit", type=int, default=None, help="проб: не больше N новых доменов")
    all_p.add_argument("--workers", type=int, default=256, help="параллелизм проб (по умолчанию 256)")
    all_p.add_argument("--https", action="store_true", help="дополнительно HTTPS HEAD-проб")
    all_p.add_argument("--no-ns", action="store_true", help="не проверять NS")
    all_p.add_argument("--provenance", action="store_true",
                       help="писать out/provenance.json.gz (страница «почему в базе»)")
    add_common(all_p)

    probe_p = sub.add_parser("probe", help="пробы доступности: DNS/NS (+ опционально HTTPS)")
    probe_p.add_argument("--input", type=Path, default=None, help="плоский файл доменов вместо out/entries.jsonl")
    probe_p.add_argument("--limit", type=int, default=None, help="проверить не больше N новых доменов")
    probe_p.add_argument("--workers", type=int, default=256, help="параллелизм проб (по умолчанию 256)")
    probe_p.add_argument("--https", action="store_true", help="дополнительно HTTPS HEAD-проб (медленнее)")
    probe_p.add_argument("--no-ns", action="store_true", help="не проверять NS (быстрее, без детекта парковки)")
    add_common(probe_p)

    resolve_p = sub.add_parser("resolve", help="IP-инвентарь: кэш проб + IP-источники")
    resolve_p.add_argument("--download-geolite", action="store_true",
                           help="скачать GeoLite2-ASN.mmdb (для ASN-аннотации)")
    resolve_p.add_argument("--geolite-mmdb", type=Path, default=None,
                           help="путь к mmdb (по умолчанию tools/GeoLite2-ASN.mmdb)")
    add_common(resolve_p)

    add_common(sub.add_parser("summarize", help="IP -> CIDR (с учётом ASN, если есть asn-map.json)"))

    emit_p = sub.add_parser("emit", help="итоговые списки + forge.toml для мастерской")
    emit_p.add_argument("--keep-dead", action="store_true",
                        help="не выбрасывать dead-домены (политика по умолчанию: выбрасывать)")
    emit_p.add_argument("--owner", default=DEFAULT_OWNER, help=f"GitHub-владелец (по умолчанию {DEFAULT_OWNER})")
    emit_p.add_argument("--repo", default=DEFAULT_REPO, help=f"имя репозитория (по умолчанию {DEFAULT_REPO})")
    emit_p.add_argument("--provenance", action="store_true",
                        help="писать out/provenance.json.gz (страница «почему в базе»)")
    add_common(emit_p)

    subs_p = sub.add_parser(
        "subscriptions",
        help="подписки: clash-meta, v2rayn, манифест + сайт (Throne/sing-box — из шаблонов мастерской)")
    subs_p.add_argument("--owner", default=DEFAULT_OWNER, help=f"GitHub-владелец (по умолчанию {DEFAULT_OWNER})")
    subs_p.add_argument("--repo", default=DEFAULT_REPO, help=f"имя репозитория (по умолчанию {DEFAULT_REPO})")
    subs_p.add_argument("--category", default="owf", help="категория geoip/geosite.dat (по умолчанию owf)")
    subs_p.add_argument("--site-dir", type=Path, default=None, help="директория сайта (по умолчанию <root>/site)")
    add_common(subs_p)

    cc_p = sub.add_parser("check-community", help="валидация community/additions.txt и exclusions.txt (ревью PR)")
    add_common(cc_p)

    geo_p = sub.add_parser("geo-dat", help="входы для конвертеров .dat/.db (xray-geoip, generate-geoip-geosite)")
    geo_p.add_argument("--category", default="owf", help="категория в geoip/geosite (по умолчанию owf)")
    add_common(geo_p)

    add_p = sub.add_parser("добавить", help="добавить домен/IP/CIDR в community/additions.txt (правка -> PR)")
    add_p.add_argument("value", help="домен (example.com), IP (203.0.113.5) или подсеть (203.0.113.0/24)")
    add_common(add_p)
    return parser


def _get(args: argparse.Namespace, name: str, default):
    value = getattr(args, name, default)
    return default if value is None and default is not None else value


def _resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    root = Path(_get(args, "root", Path("."))).resolve()
    config = _get(args, "config", None)
    config = config.resolve() if config else root / "pipeline" / "sources.toml"
    output = _get(args, "output", None)
    output = output.resolve() if output else root / "out"
    return root, config, output


# --- collect / classify (M0) ---

def _collect(root: Path, config: Path, args: argparse.Namespace) -> tuple[list[Entry], list[str]]:
    try:
        sources = load_sources(config)
    except Exception as exc:  # noqa: BLE001 — ошибки конфига фатальны
        print(f"config error: {exc}")
        raise SystemExit(EXIT_CONFIG_ERROR) from exc
    if _get(args, "verbose", False):
        print(f"sources: {[s.name for s in sources]}")
    entries: list[Entry] = []
    warnings: list[str] = []
    for src in sources:
        got, err = collect_source(src, root, offline=_get(args, "offline", False))
        if err is not None:
            warnings.append(err)
        else:
            entries.extend(got)
        if _get(args, "verbose", False):
            print(f"  {src.name:<24} {len(got):>6}  [{src.kind}/{src.tier}]")
    merged: dict[tuple[str, str], Entry] = {}
    for e in entries:
        key = (e.kind, e.value)
        prev = merged.get(key)
        if prev is None:
            merged[key] = e
        else:
            prev.evidence.extend(e.evidence)  # один домен из разных источников
    return list(merged.values()), warnings


def _classify(entries: list[Entry], output: Path) -> None:
    exclusions = [e for e in entries if e.kind == "exclusion"]
    domains = [e for e in entries if e.kind != "exclusion"]
    kept, removed = apply_exclusions(domains, exclusions)
    for e in kept:
        flag_heuristics(e)
    out_path = output / "entries.jsonl"
    save_entries(kept, out_path)
    print(f"classified: kept {len(kept)}, excluded {len(removed)} -> {out_path}")


def _report(warnings: list[str], args: argparse.Namespace) -> int:
    for w in warnings:
        print(f"  warn: {w}")
    if _get(args, "strict", False) and warnings:
        return EXIT_SOURCE_WARNINGS
    return EXIT_OK


# --- probe / resolve / summarize / emit (M1) ---

def _load_domains_for_probe(input_path: Path | None, output: Path) -> list[str]:
    if input_path is not None:
        lines = input_path.read_text(encoding="utf-8").splitlines()
        return [c for c in (sanitize_line(line) for line in lines) if c]
    entries = load_entries(output / "entries.jsonl")
    return [e.value for e in entries if e.kind == "domain"]


def cmd_probe(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import probe as probe_mod

    if not probe_mod.HAS_DNSPYTHON:
        print("dnspython не установлен: pip install dnspython")
        return EXIT_CONFIG_ERROR
    domains = _load_domains_for_probe(_get(args, "input", None), output)
    if not domains:
        print("нет доменов для проб: сначала 'build' или укажи --input")
        return EXIT_CONFIG_ERROR
    cache_path = output / "probe-cache.json"
    cache = probe_mod.load_cache(cache_path)
    stats = asyncio.run(probe_mod.probe_domains(
        domains, cache,
        workers=int(_get(args, "workers", 256)),
        https=bool(_get(args, "https", False)),
        ns_check=not _get(args, "no_ns", False),
        limit=_get(args, "limit", None),
        verbose=_get(args, "verbose", False),
    ))
    probe_mod.save_cache(cache_path, cache)
    print("probe: " + "  ".join(f"{k}={v}" for k, v in stats.items()))
    print(f"cache: {len(cache)} domains -> {cache_path}")
    return EXIT_OK


def cmd_resolve(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import probe as probe_mod
    from . import resolve as resolve_mod
    from .emit import write_lines

    entries_path = output / "entries.jsonl"
    entries = load_entries(entries_path) if entries_path.exists() else []
    cache = probe_mod.load_cache(output / "probe-cache.json")
    resolved = probe_mod.collect_ips_from_cache(cache)
    source_ips = resolve_mod.collect_ips_from_entries(entries)
    all_ips = list(dict.fromkeys(resolved + source_ips))
    write_lines(output / "ips-all.lst", all_ips)

    asn_map: dict = {}
    mmdb = _get(args, "geolite_mmdb", None) or (root / "tools" / "GeoLite2-ASN.mmdb")
    if _get(args, "download_geolite", False):
        try:
            resolve_mod.download_geolite(mmdb)
        except Exception as exc:  # noqa: BLE001 — mmdb опционален
            print(f"  warn: geolite download failed: {exc}")
    if mmdb.exists():
        if resolve_mod.HAS_GEOIP2:
            asn_map = resolve_mod.annotate_asn(all_ips, mmdb)
            (output / "asn-map.json").write_text(json.dumps(asn_map, ensure_ascii=False), encoding="utf-8")
        else:
            print("  warn: GeoLite2-ASN.mmdb есть, но geoip2 не установлен (pip install geoip2)")
    print(f"resolve: {len(resolved)} resolved + {len(source_ips)} source -> {len(all_ips)} ips; asn={len(asn_map)}")
    return EXIT_OK


def cmd_summarize(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import summarize as summarize_mod
    from .emit import write_lines

    path = output / "ips-all.lst"
    if not path.exists():
        print("нет out/ips-all.lst — сначала 'resolve'")
        return EXIT_CONFIG_ERROR
    ips = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    asn_map: dict = {}
    map_path = output / "asn-map.json"
    if map_path.exists():
        try:
            asn_map = json.loads(map_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            asn_map = {}
    cidrs, report = summarize_mod.summarize(ips, asn_map)
    write_lines(output / "ipsum.lst", cidrs)
    (output / "asn-summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"summarize: {report['input_ips']} ips -> {len(cidrs)} cidrs in {report['groups_count']} groups")
    return EXIT_OK


def cmd_emit(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import emit as emit_mod
    from . import probe as probe_mod
    from .resolve import collect_ips_from_entries

    entries_path = output / "entries.jsonl"
    if not entries_path.exists():
        print("нет out/entries.jsonl — сначала 'build'")
        return EXIT_CONFIG_ERROR
    entries = load_entries(entries_path)
    cache = probe_mod.load_cache(output / "probe-cache.json")
    keep_dead = bool(_get(args, "keep_dead", False))
    kept, stats = emit_mod.apply_policy(entries, cache, keep_dead=keep_dead)
    domains = [e.value for e in kept]

    ipsum = output / "ipsum.lst"
    if ipsum.exists():
        ips = [line.strip() for line in ipsum.read_text(encoding="utf-8").splitlines() if line.strip()]
        ips_source = "ipsum"
    else:
        ips = collect_ips_from_entries(entries)
        ips_source = "entries (ipsum отсутствует — сырые IP/CIDR)"

    domains_path = output / "owf-domains.lst"
    ips_path = output / "owf-ips.lst"
    emit_mod.write_lines(domains_path, domains)
    emit_mod.write_lines(ips_path, ips)

    owner = _get(args, "owner", DEFAULT_OWNER)
    repo = _get(args, "repo", DEFAULT_REPO)
    forge_path = root / "forge.toml"
    forge_path.write_text(
        emit_mod.render_forge_toml(domains_path.resolve(), ips_path.resolve(), owner, repo),
        encoding="utf-8")

    emit_mod.write_report(output / "emit-report.json", {
        "policy": {"drop_dead": not keep_dead},
        "domains": stats,
        "domains_list": len(domains),
        "ips_list": len(ips),
        "ips_source": ips_source,
        "forge_toml": str(forge_path.resolve()),
    })
    print(f"emit: domains={len(domains)} (dropped dead: {stats['dropped_dead']}), ips={len(ips)} [{ips_source}]")
    print(f"forge.toml -> {forge_path}")

    if _get(args, "provenance", False):
        prov = emit_mod.build_provenance(entries, cache)
        prov_path = output / "provenance.json.gz"
        size = emit_mod.write_provenance_gz(prov, prov_path)
        print(f"provenance: {len(prov)} entries -> {prov_path} ({size} bytes gz)")
    return EXIT_OK


def cmd_subscriptions(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import subscriptions as subs_mod

    owner = _get(args, "owner", DEFAULT_OWNER)
    repo = _get(args, "repo", DEFAULT_REPO)
    category = _get(args, "category", "owf")
    site_dir = _get(args, "site_dir", None) or (root / "site")
    artifacts = subs_mod.render_all(owner, repo, category)
    written = subs_mod.write_all(artifacts, output, site_dir)
    print("subscriptions: clash-meta, v2rayn, manifest + site/index.html")
    for w in written:
        print(f"  wrote {w}")
    return EXIT_OK


def cmd_check_community(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import community_check as cc

    report = cc.check_community(root)
    for err in report["errors"]:
        print(f"  error: {err}")
    print("check-community: " + json.dumps(report["stats"], ensure_ascii=False))
    if report["errors"]:
        print(f"check-community: {len(report['errors'])} ошибок — правку нужно поправить")
        return EXIT_CONFIG_ERROR
    print("check-community: ok")
    return EXIT_OK


def cmd_geodat(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from . import geo_dat as geo_mod

    report = geo_mod.prepare_all(root, output, name=_get(args, "category", "owf"))
    print("geo-dat: входы для конвертеров подготовлены (сама сборка бинарников — в CI, нужен Go)")
    for key, value in report.items():
        print(f"  {key}: {value}")
    return EXIT_OK


def cmd_add(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    from .collect import detect_kind, sanitize_line

    clean = sanitize_line(args.value)
    if clean is None or detect_kind(clean) is None:
        print(
            f"не удалось распознать: {args.value!r}\n"
            "добавить можно домен (example.com), IP (203.0.113.5) или подсеть (203.0.113.0/24);\n"
            "исключения и правила — в community/exclusions.txt"
        )
        return EXIT_CONFIG_ERROR

    path = root / "community" / "additions.txt"
    present: set[str] = set()
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            c = sanitize_line(raw)
            if c:
                present.add(c)
    if clean in present:
        print(f"уже в списке: {clean} (community/additions.txt) — ничего не меняю")
        return EXIT_OK

    path.parent.mkdir(parents=True, exist_ok=True)
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    with path.open("a", encoding="utf-8") as fh:
        if text and not text.endswith("\n"):
            fh.write("\n")
        fh.write(clean + "\n")
    print(f"добавлено: {clean}")
    print("Правка добавлена в community/additions.txt — отправь PR на GitHub")
    return EXIT_OK


def cmd_all(args: argparse.Namespace, root: Path, config: Path, output: Path) -> int:
    verbose = _get(args, "verbose", False)

    entries, warnings = _collect(root, config, args)
    save_entries(entries, output / "raw-entries.jsonl")
    print(f"collected {len(entries)} unique entries -> raw-entries.jsonl")
    _classify(entries, output)
    rc = _report(warnings, args)
    if rc != EXIT_OK:
        return rc

    if _get(args, "offline", False):
        print("  warn: probe пропущен (--offline); resolve использует существующий кэш")
    else:
        probe_args = argparse.Namespace(
            input=None,
            limit=_get(args, "limit", None),
            workers=int(_get(args, "workers", 256)),
            https=bool(_get(args, "https", False)),
            no_ns=bool(_get(args, "no_ns", False)),
            verbose=verbose,
        )
        rc = cmd_probe(probe_args, root, config, output)
        if rc != EXIT_OK:
            return rc

    resolve_args = argparse.Namespace(download_geolite=False, geolite_mmdb=None, verbose=verbose)
    rc = cmd_resolve(resolve_args, root, config, output)
    if rc != EXIT_OK:
        return rc
    rc = cmd_summarize(argparse.Namespace(verbose=verbose), root, config, output)
    if rc != EXIT_OK:
        return rc
    emit_args = argparse.Namespace(keep_dead=False, owner=DEFAULT_OWNER, repo=DEFAULT_REPO,
                                   provenance=_get(args, "provenance", False), verbose=verbose)
    rc = cmd_emit(emit_args, root, config, output)
    if rc != EXIT_OK:
        return rc
    subs_args = argparse.Namespace(owner=DEFAULT_OWNER, repo=DEFAULT_REPO, category="owf",
                                   site_dir=None, verbose=verbose)
    return cmd_subscriptions(subs_args, root, config, output)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root, config, output = _resolve_paths(args)
    output.mkdir(parents=True, exist_ok=True)

    if args.command in ("collect", "build"):
        entries, warnings = _collect(root, config, args)
        raw_path = output / "raw-entries.jsonl"
        save_entries(entries, raw_path)
        print(f"collected {len(entries)} unique entries -> {raw_path}")
        if args.command == "build":
            _classify(entries, output)
        return _report(warnings, args)

    if args.command == "probe":
        return cmd_probe(args, root, config, output)
    if args.command == "resolve":
        return cmd_resolve(args, root, config, output)
    if args.command == "summarize":
        return cmd_summarize(args, root, config, output)
    if args.command == "emit":
        return cmd_emit(args, root, config, output)
    if args.command == "all":
        return cmd_all(args, root, config, output)
    if args.command == "subscriptions":
        return cmd_subscriptions(args, root, config, output)
    if args.command == "check-community":
        return cmd_check_community(args, root, config, output)
    if args.command == "geo-dat":
        return cmd_geodat(args, root, config, output)
    if args.command == "добавить":
        return cmd_add(args, root, config, output)

    # classify отдельно: читаем результат collect
    raw_path = output / "raw-entries.jsonl"
    if not raw_path.exists():
        print(f"missing {raw_path} — сначала запусти 'collect' или 'build'")
        return EXIT_CONFIG_ERROR
    _classify(load_entries(raw_path), output)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
