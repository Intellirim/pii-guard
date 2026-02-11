"""Command-line interface for pii-guard."""

import sys
import click
from pathlib import Path
from typing import Optional

from pii_shield import __version__
from pii_shield.scanner import Scanner
from pii_shield.masker import Masker
from pii_shield.models import MaskingStrategy
from pii_shield.formatters import TextFormatter, JSONFormatter, CSVFormatter
from pii_shield.patterns import PATTERNS, get_pattern_categories, get_pattern_info


@click.group()
@click.version_option(version=__version__)
def cli():
    """pii-guard: Context-aware PII detection for LLM pipelines and data workflows."""
    # Main CLI group - subcommands are registered via decorators


@cli.command()
@click.argument('path', required=False)
@click.option('--stdin', is_flag=True, help='Read from stdin')
@click.option('--threshold', '-t', type=int, default=70, help='Confidence threshold (0-100)')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'csv']), default='text', help='Output format')
@click.option('--mask', '-m', type=click.Choice(['full', 'partial', 'hash', 'token']), help='Masking strategy')
@click.option('--output', '-o', type=click.Path(), help='Output file for masked content')
def scan(
    path: Optional[str],
    stdin: bool,
    threshold: int,
    format: str,
    mask: Optional[str],
    output: Optional[str]
):
    """
    Scan files or directories for PII.

    Examples:
      pii-guard scan input.txt
      pii-guard scan --format json ./logs/
      echo "test" | pii-guard scan --stdin --mask full
    """
    scanner = Scanner(threshold=threshold)

    if stdin:
        # Read from stdin
        text = sys.stdin.read()
        result = scanner.scan_text(text, "<stdin>")
        results = [result]

        if mask:
            # Apply masking to stdin
            masker = Masker(strategy=MaskingStrategy(mask))
            masked_text = _apply_masking(text, result, masker)
            click.echo(masked_text)
            return
    elif path:
        # Scan file or directory
        p = Path(path)
        if p.is_file():
            result = scanner.scan_file(path)
            results = [result]
        elif p.is_dir():
            results = scanner.scan_directory(path)
        else:
            click.echo(f"Error: Path not found: {path}", err=True)
            sys.exit(1)
    else:
        click.echo("Error: Provide PATH argument or use --stdin", err=True)
        sys.exit(1)

    # Handle masking with output file
    if mask and output and not stdin:
        masking_strategy = MaskingStrategy(mask)
        masker = Masker(strategy=masking_strategy)

        if len(results) == 1:
            # Single file
            with open(path, 'r', encoding='utf-8') as f:
                text = f.read()
            masked_text = _apply_masking(text, results[0], masker)

            with open(output, 'w', encoding='utf-8') as f:
                f.write(masked_text)

            click.echo(f"Scanning: {path}")
            click.echo(f"Masking mode: {mask}\n")
            click.echo("Processed 1 file:")
            click.echo(f"- Masked {len(results[0].matches)} PII instances")
            click.echo(f"- Output written to: {output}\n")

            # Show masked patterns
            if results[0].summary:
                click.echo("Masked patterns:")
                for match in results[0].matches[:3]:  # Show first 3
                    masked_val = masker.mask(match.value, match.type)
                    click.echo(f"  {match.type}: {masked_val}")
        else:
            click.echo("Error: --output only supported for single files", err=True)
            sys.exit(1)

        return

    # Format output
    if format == 'json':
        formatter = JSONFormatter()
    elif format == 'csv':
        formatter = CSVFormatter()
    else:
        formatter = TextFormatter()

    output_text = formatter.format(results)
    click.echo(output_text)

    # Exit with error if PII found
    total_matches = sum(len(r.matches) for r in results)
    if total_matches > 0:
        sys.exit(1)


@cli.command()
@click.option('--list', 'list_patterns', is_flag=True, help='List all supported patterns')
@click.option('--show', type=str, help='Show details for a specific pattern type')
def patterns(list_patterns: bool, show: Optional[str]):
    """
    List or show details about supported PII patterns.

    Examples:
      pii-guard patterns --list
      pii-guard patterns --show EMAIL
    """
    if show:
        if show in PATTERNS:
            pattern, confidence, description = PATTERNS[show]
            click.echo(f"Pattern: {show}")
            click.echo(f"Description: {description}")
            click.echo(f"Base confidence: {confidence}")
            click.echo(f"Regex: {pattern.pattern}")
        else:
            click.echo(f"Error: Unknown pattern type: {show}", err=True)
            sys.exit(1)

    elif list_patterns:
        click.echo(f"Supported PII Patterns ({len(PATTERNS)} total):\n")

        categories = get_pattern_categories()

        for category, pattern_list in categories.items():
            click.echo(f"{category}:")
            for pattern_type in pattern_list:
                if pattern_type in PATTERNS:
                    description = get_pattern_info(pattern_type)
                    click.echo(f"  {pattern_type:<20} {description}")
            click.echo()

        click.echo("Use 'pii-guard patterns --show <TYPE>' for pattern details")
    else:
        click.echo("Use --list to show all patterns or --show TYPE for details")


@cli.command()
def config():
    """Show current configuration."""
    click.echo("pii-guard configuration:")
    click.echo(f"  Version: {__version__}")
    click.echo(f"  Default threshold: 70")
    click.echo(f"  Supported patterns: {len(PATTERNS)}")
    click.echo(f"  Output formats: text, json, csv")
    click.echo(f"  Masking strategies: full, partial, hash, token")


def _apply_masking(text: str, result, masker: Masker) -> str:
    """Apply masking to text based on scan result."""
    # Sort matches by position (reverse order to maintain positions)
    sorted_matches = sorted(result.matches, key=lambda m: (m.line, m.column), reverse=True)

    lines = text.split('\n')

    for match in sorted_matches:
        if match.line <= len(lines):
            line = lines[match.line - 1]
            masked_value = masker.mask(match.value, match.type)

            # Find and replace the value in the line
            if match.value in line:
                line = line.replace(match.value, masked_value, 1)
                lines[match.line - 1] = line

    return '\n'.join(lines)


def main():
    """Entry point for CLI."""
    cli()


if __name__ == '__main__':
    main()
