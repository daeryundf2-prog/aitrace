from __future__ import annotations

from importlib.metadata import distributions
from pathlib import Path
from typing import Annotated

import typer

from aitrace import __version__, pipeline
from aitrace.pipeline import AnalyzeOptions, PipelineError, PipelineResult
from aitrace.plugins.registry import load_plugins

app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="Forensic AI-usage tracing for disk images."
)


def _formats(value: str) -> tuple[str, ...]:
    try:
        return pipeline.parse_formats(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _lang(value: str | None) -> str | None:
    if value is not None and value not in pipeline.LANGS:
        raise typer.BadParameter(f"choose one of {', '.join(pipeline.LANGS)}")
    return value


def _fail(exc: PipelineError) -> typer.Exit:
    typer.echo(f"error: {exc}", err=True)
    return typer.Exit(code=exc.exit_code)


def _print_result(result: PipelineResult) -> None:
    width = max(len(name) for name in result.counts) if result.counts else 0
    typer.echo("section".ljust(width) + "  count")
    for name, count in result.counts.items():
        typer.echo(f"{name.ljust(width)}  {count}")
    for evidence_id, status in sorted(result.verification.items()):
        typer.echo(f"evidence {evidence_id}: {status}")
    typer.echo("reports (sha256):")
    for rendered in result.reports:
        typer.echo(f"  {rendered.sha256}  {rendered.case_relative_path}")
    typer.echo(f"case dir: {result.case_dir}")


@app.command()
def analyze(
    images: Annotated[list[Path], typer.Argument(help="Evidence image(s): E01, raw, or a directory tree.")],
    case_dir: Annotated[Path, typer.Option("--case-dir", help="Output case directory.")],
    case_name: Annotated[str, typer.Option("--case-name")] = "",
    case_number: Annotated[str, typer.Option("--case-number")] = "",
    examiner: Annotated[str, typer.Option("--examiner")] = "",
    org: Annotated[str, typer.Option("--org")] = "",
    tz: Annotated[str, typer.Option("--tz")] = "Asia/Seoul",
    lang: Annotated[str, typer.Option("--lang", callback=_lang)] = "ko",
    formats: Annotated[str, typer.Option("--formats")] = ",".join(pipeline.FORMATS),
    no_export: Annotated[bool, typer.Option("--no-export")] = False,
    no_media_hash: Annotated[bool, typer.Option("--no-media-hash")] = False,
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Analyze evidence into a case directory and render reports."""
    opts = AnalyzeOptions(
        images=tuple(images),
        case_dir=case_dir,
        case_name=case_name,
        case_number=case_number,
        examiner=examiner,
        org=org,
        tz=tz,
        lang=lang,
        formats=_formats(formats),
        export=not no_export,
        media_hash=not no_media_hash,
        force=force,
    )
    try:
        result = pipeline.analyze(opts)
    except PipelineError as exc:
        raise _fail(exc) from exc
    _print_result(result)
    if result.exit_code != pipeline.EXIT_OK:
        typer.echo("error: evidence integrity mismatch; report written with an INTEGRITY finding", err=True)
        raise typer.Exit(code=result.exit_code)


@app.command()
def verify(image: Annotated[Path, typer.Argument(help="E01 (first segment) or raw image.")]) -> None:
    """Print segment and media hashes of an image."""
    try:
        intake = pipeline.verify_image(image)
    except PipelineError as exc:
        raise _fail(exc) from exc
    typer.echo(f"kind: {intake['kind']}")
    for seg in intake["segments"]:
        typer.echo(f"segment {seg['name']} size={seg['size']}")
        for algo in ("md5", "sha1", "sha256"):
            typer.echo(f"  {algo}: {seg[algo]}")
    typer.echo(f"media sha256: {intake['media_sha256']}")
    if intake["acquisition_hashes"]:
        for algo, value in sorted(intake["acquisition_hashes"].items()):
            typer.echo(f"stored {algo}: {value}")
    for limitation in intake["limitations"]:
        typer.echo(f"note: {limitation}")


@app.command()
def report(
    case_dir: Annotated[Path, typer.Option("--case-dir", help="Existing case directory.")],
    lang: Annotated[str | None, typer.Option("--lang", callback=_lang)] = None,
    formats: Annotated[str, typer.Option("--formats")] = ",".join(pipeline.FORMATS),
    case_name: Annotated[str, typer.Option("--case-name")] = "",
    case_number: Annotated[str, typer.Option("--case-number")] = "",
    examiner: Annotated[str, typer.Option("--examiner")] = "",
    org: Annotated[str, typer.Option("--org")] = "",
) -> None:
    """Re-render reports from case.sqlite after verifying the custody chain; case details given here replace
    the ones entered at analysis for this rendering and are recorded in the custody log."""
    details = {"name": case_name, "number": case_number, "examiner": examiner, "organisation": org}
    try:
        result = pipeline.report(case_dir, lang, _formats(formats), details)
    except PipelineError as exc:
        raise _fail(exc) from exc
    _print_result(result)


@app.command()
def plugins() -> None:
    """List artifact plugins."""
    loaded = load_plugins()
    name_w = max((len(p.name) for p in loaded), default=4)
    ver_w = max((len(p.version) for p in loaded), default=7)
    typer.echo(f"{'name'.ljust(name_w)}  {'version'.ljust(ver_w)}  description")
    for plugin in loaded:
        typer.echo(f"{plugin.name.ljust(name_w)}  {plugin.version.ljust(ver_w)}  {plugin.description}")


@app.command()
def version() -> None:
    """Print aitrace and dissect versions."""
    typer.echo(f"aitrace {__version__}")
    dissect = sorted(
        {(d.metadata["Name"], d.version) for d in distributions() if d.metadata["Name"].startswith("dissect")}
    )
    for name, ver in dissect:
        typer.echo(f"{name} {ver}")


if __name__ == "__main__":
    app()
