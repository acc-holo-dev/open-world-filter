"""Command-line entry point: python -m routeforge <command>."""

from __future__ import annotations

import argparse

from . import __version__, check, init, notes, profiles, render, validate

DEFAULT_ROOT = render.DEFAULT_ROOT


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routeforge",
        description="Source-driven route-set builder for Throne and sing-box.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    build = sub.add_parser("build", help="build rule-sets and profiles from rules/, templates/ and forge.toml")
    build.add_argument("--strict", action="store_true",
                      help="fail on invalid entries or failed downloads (used in CI)")
    build.add_argument("--dry-run", action="store_true", help="run the full build but write nothing")
    build.add_argument("--offline", action="store_true", help="use only cached external sources")
    build.add_argument("--no-cache", action="store_true", help="disable the external source cache")
    build.add_argument("--no-profiles", action="store_true", help="skip profile rendering")
    build.add_argument("--cache-ttl", type=int, default=6 * 3600,
                       help="cache lifetime in seconds; negative disables expiry (default 21600)")
    build.add_argument("--jobs", type=int, default=4, help="parallel external source downloads (default 4)")
    build.add_argument("--root", default=str(DEFAULT_ROOT), help="build root (default: repository root)")
    build.add_argument("--output-dir", help="output directory (default: <root>/release-assets)")
    build.add_argument("--cache-dir", help="cache directory (default: <root>/.source-cache)")
    build.add_argument("--previous-dir", help="directory with previous rule-set JSON files; "
                                              "produces changes-report.json")
    build.add_argument("--verbose", action="store_true", help="print per-source details")

    validate_p = sub.add_parser("validate", help="validate generated outputs, checksums, and the manifest")
    validate_p.add_argument("--root", default=str(DEFAULT_ROOT), help="build root")
    validate_p.add_argument("--dir", help="directory with generated outputs (default: <root>/release-assets)")
    validate_p.add_argument("--require-manifest", action="store_true",
                            help="fail when build-manifest.json is missing")
    validate_p.add_argument("--strict", action="store_true", help="also fail on warnings")

    notes_p = sub.add_parser("notes", help="render release notes from the build manifest")
    notes_p.add_argument("--manifest", required=True, help="path to build-manifest.json")
    notes_p.add_argument("--changes", help="path to changes-report.json (optional)")
    notes_p.add_argument("--sing-box-version", help="sing-box version used to compile the .srs assets")
    notes_p.add_argument("--note", help="extra note section (e.g. manual trigger reason)")
    notes_p.add_argument("--output", help="write markdown to this file instead of stdout")

    profiles_p = sub.add_parser("profiles", help="render only the Throne/sing-box profiles")
    profiles_p.add_argument("--root", default=None, help="build root (default: current directory)")
    profiles_p.add_argument("--output-dir", help="output directory (default: <root>/release-assets)")

    init_p = sub.add_parser("init", help="scaffold a new routeforge workspace")
    init_p.add_argument("directory", nargs="?", default=".",
                        help="target directory (default: current directory)")
    init_p.add_argument("--force", action="store_true", help="overwrite existing files")

    check_p = sub.add_parser("check", help="health-check the forge: config, sources, freshness, sing-box")
    check_p.add_argument("--root", default=None, help="build root (default: current directory)")
    check_p.add_argument("--offline", action="store_true", help="skip source reachability checks")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "build":
        return render.build_command(args)
    if args.command == "validate":
        return validate.command(args)
    if args.command == "notes":
        return notes.command(args)
    if args.command == "profiles":
        return profiles.profiles_command(args)
    if args.command == "init":
        return init.init_command(args)
    if args.command == "check":
        return check.check_command(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
