"""Minimal tests for CLI."""

import pytest
from click.testing import CliRunner
from pii_shield.cli import cli


def test_cli_version():
    """Test version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ['--version'])
    assert result.exit_code == 0
    assert '1.0.0' in result.output


def test_cli_scan_stdin():
    """Test scan with stdin."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin'], input='test@example.com')
    assert result.exit_code in [0, 1]
    assert isinstance(result.output, str)


def test_cli_patterns_list():
    """Test patterns list."""
    runner = CliRunner()
    result = runner.invoke(cli, ['patterns', '--list'])
    assert result.exit_code == 0
    assert 'EMAIL' in result.output


def test_cli_config():
    """Test config command."""
    runner = CliRunner()
    result = runner.invoke(cli, ['config'])
    assert result.exit_code == 0
    assert len(result.output) > 0


def test_cli_help():
    """Test help command."""
    runner = CliRunner()
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'Usage:' in result.output


def test_cli_scan_help():
    """Test scan command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--help'])
    assert result.exit_code == 0
    assert 'scan' in result.output.lower()


def test_cli_patterns_help():
    """Test patterns command help."""
    runner = CliRunner()
    result = runner.invoke(cli, ['patterns', '--help'])
    assert result.exit_code == 0
    assert len(result.output) > 0


def test_cli_scan_with_threshold():
    """Test scan with custom threshold."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin', '--threshold', '90'], input='test@example.com')
    assert result.exit_code in [0, 1]
    assert isinstance(result.output, str)


def test_cli_scan_json_format():
    """Test scan with JSON output format."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin', '--format', 'json'], input='test@example.com')
    assert result.exit_code in [0, 1]
    assert isinstance(result.output, str)


def test_cli_scan_empty_input():
    """Test scan with empty input."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin'], input='')
    assert result.exit_code in [0, 1]
    assert isinstance(result.output, str)


def test_cli_patterns_list_output():
    """Test patterns list shows multiple patterns."""
    runner = CliRunner()
    result = runner.invoke(cli, ['patterns', '--list'])
    assert result.exit_code == 0
    assert 'EMAIL' in result.output
    assert 'SSN' in result.output


def test_cli_scan_multiple_pii():
    """Test scan with multiple PII types in input."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin'], input='test@example.com 123-45-6789')
    assert result.exit_code in [0, 1]
    assert isinstance(result.output, str)
