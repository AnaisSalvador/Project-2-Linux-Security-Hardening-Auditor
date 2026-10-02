import pytest

from hardening_auditor.cli import build_parser


def test_cli_default_output_directory():
    parser = build_parser()

    args = parser.parse_args([])

    assert args.output_dir == "reports"


def test_cli_custom_output_directory():
    parser = build_parser()

    args = parser.parse_args(
        ["--output-dir", "custom-reports"]
    )

    assert args.output_dir == "custom-reports"


def test_cli_help():
    parser = build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])

    assert exc_info.value.code == 0
