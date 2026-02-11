"""Minimal tests for CLI."""

import pytest
from click.testing import CliRunner
from pii_guard.cli import cli


def test_cli_version():
    """Test version command."""
    runner = CliRunner()
    result = runner.invoke(cli, ['--version'])
    assert result.exit_code == 0


def test_cli_scan_stdin():
    """Test scan with stdin."""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '--stdin'], input='test@example.com')
    assert result.exit_code in [0, 1]


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
