"""Tests for hardening_auditor.system (SystemInfo and FakeSystemInfo).

The real SystemInfo is tested against temporary files and a harmless
Python subprocess. SystemInfo itself never writes anything; only these
tests create files, inside pytest's tmp_path.

Platform notes
--------------
* Runs everywhere: FakeSystemInfo tests, source read-only audit, command
  validation, run_command, and the OS-neutral parts of the file tests.
* @linux_only: tests that assert POSIX behaviour (permission bits, owners,
  symlinks, geteuid). They are skipped on Windows and run on Linux.
* @skip_if_root: Linux tests that cannot work as root, because root
  ignores file permissions.
"""

import ast
import inspect
import os
import socket
import sys
from pathlib import Path

import pytest

from hardening_auditor import system
from hardening_auditor.system import (
    ALLOWED_COMMANDS,
    ErrorKind,
    FakeSystemInfo,
    FindPredicate,
    SystemInfo,
    _parse_pretty_name,
)

IS_LINUX = sys.platform.startswith("linux")
running_as_root = IS_LINUX and os.geteuid() == 0

linux_only = pytest.mark.skipif(
    not IS_LINUX,
    reason="requires Linux (POSIX permissions, ownership, symlinks, geteuid)",
)
skip_if_root = pytest.mark.skipif(
    running_as_root, reason="root ignores file permissions, so the test cannot work"
)


@pytest.fixture
def sysinfo():
    return SystemInfo()


@pytest.fixture
def allow_python(monkeypatch):
    """Let tests run the current Python interpreter (and a fake missing tool)."""
    allowed = frozenset({os.path.basename(sys.executable), "definitely-not-a-real-tool"})
    monkeypatch.setattr(system, "ALLOWED_COMMANDS", allowed)


# ===========================================================================
# SystemInfo: read_file
# ===========================================================================

def test_read_file_returns_text(sysinfo, tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("hello\n")

    result = sysinfo.read_file(str(path))

    assert result.ok
    assert result.error is None
    assert result.text == "hello\n"


def test_read_file_missing_is_not_found(sysinfo, tmp_path):
    result = sysinfo.read_file(str(tmp_path / "missing.txt"))

    assert not result.ok
    assert result.error == ErrorKind.NOT_FOUND
    assert result.text == ""


@linux_only
def test_read_file_path_through_a_file_is_not_found(sysinfo, tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("x")

    result = sysinfo.read_file(str(path / "child"))

    assert result.error == ErrorKind.NOT_FOUND


@linux_only
@skip_if_root
def test_read_file_permission_denied(sysinfo, tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text("secret")
    path.chmod(0o000)

    result = sysinfo.read_file(str(path))

    assert result.error == ErrorKind.PERMISSION_DENIED
    assert "secret" not in result.text


@linux_only
def test_read_file_on_directory_is_unexpected(sysinfo, tmp_path):
    result = sysinfo.read_file(str(tmp_path))

    assert result.error == ErrorKind.UNEXPECTED


def test_read_file_replaces_undecodable_bytes(sysinfo, tmp_path):
    path = tmp_path / "binary.txt"
    path.write_bytes(b"ok\xff\xfe")

    result = sysinfo.read_file(str(path))

    assert result.ok
    assert result.text.startswith("ok")


# ===========================================================================
# SystemInfo: list_dir
# ===========================================================================

def test_list_dir_returns_sorted_names(sysinfo, tmp_path):
    (tmp_path / "b").write_text("")
    (tmp_path / "a").write_text("")

    result = sysinfo.list_dir(str(tmp_path))

    assert result.ok
    assert result.entries == ["a", "b"]


def test_list_dir_missing_is_not_found(sysinfo, tmp_path):
    result = sysinfo.list_dir(str(tmp_path / "missing"))

    assert result.error == ErrorKind.NOT_FOUND
    assert result.entries == []


@linux_only
def test_list_dir_on_a_file_is_not_found(sysinfo, tmp_path):
    path = tmp_path / "a.txt"
    path.write_text("x")

    assert sysinfo.list_dir(str(path)).error == ErrorKind.NOT_FOUND


# ===========================================================================
# SystemInfo: stat_path
# ===========================================================================

@linux_only
def test_stat_path_reports_mode_owner_and_type(sysinfo, tmp_path):
    import pwd  # Unix-only module, so imported inside the Linux-only test
    path = tmp_path / "a.txt"
    path.write_text("x")
    path.chmod(0o640)

    result = sysinfo.stat_path(str(path))

    assert result.ok
    assert result.mode == 0o640
    assert result.uid == os.geteuid()
    assert result.owner == pwd.getpwuid(os.geteuid()).pw_name
    assert result.is_file
    assert not result.is_dir


@linux_only
def test_stat_path_keeps_special_permission_bits(sysinfo, tmp_path):
    path = tmp_path / "suid_file"
    path.write_text("x")
    path.chmod(0o4755)

    assert sysinfo.stat_path(str(path)).mode == 0o4755


@linux_only
def test_stat_path_on_directory(sysinfo, tmp_path):
    result = sysinfo.stat_path(str(tmp_path))

    assert result.is_dir
    assert not result.is_file


def test_stat_path_missing_is_not_found(sysinfo, tmp_path):
    result = sysinfo.stat_path(str(tmp_path / "missing"))

    assert not result.ok
    assert result.error == ErrorKind.NOT_FOUND


# ===========================================================================
# SystemInfo: run_command
# ===========================================================================

def test_run_command_captures_stdout(sysinfo, allow_python):
    result = sysinfo.run_command([sys.executable, "-c", "print('hello')"])

    assert result.ok
    assert result.stdout == "hello\n"
    assert result.returncode == 0


def test_run_command_nonzero_exit_is_still_ok(sysinfo, allow_python):
    code = "import sys; sys.stderr.write('oops'); sys.exit(3)"

    result = sysinfo.run_command([sys.executable, "-c", code])

    assert result.ok
    assert result.returncode == 3
    assert result.stderr == "oops"


def test_run_command_tool_not_found(sysinfo, allow_python):
    result = sysinfo.run_command(["definitely-not-a-real-tool"])

    assert not result.ok
    assert result.error == ErrorKind.TOOL_NOT_FOUND


def test_run_command_timeout(sysinfo, allow_python):
    result = sysinfo.run_command(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5
    )

    assert result.error == ErrorKind.TIMEOUT


def test_run_command_does_not_use_a_shell(sysinfo, allow_python):
    # Shell metacharacters must arrive as plain text, not be interpreted.
    code = "import sys; print(sys.argv[1])"

    result = sysinfo.run_command([sys.executable, "-c", code, "a; echo hacked"])

    assert result.stdout == "a; echo hacked\n"


def test_run_command_rejects_shell_string(sysinfo):
    with pytest.raises(ValueError):
        sysinfo.run_command("ss -tulnp")


def test_run_command_rejects_empty_list(sysinfo):
    with pytest.raises(ValueError):
        sysinfo.run_command([])


def test_run_command_rejects_non_string_arguments(sysinfo):
    with pytest.raises(ValueError):
        sysinfo.run_command(["ss", 1])


@pytest.mark.parametrize("args", [["rm", "-rf", "/"], ["bash", "-c", "echo hi"], ["/bin/rm", "x"]])
def test_run_command_rejects_commands_not_on_allowlist(sysinfo, args):
    with pytest.raises(ValueError):
        sysinfo.run_command(args)


def test_allowlist_contains_no_obviously_dangerous_programs():
    dangerous = {"rm", "mv", "dd", "chmod", "chown", "sh", "bash", "python", "python3", "curl", "wget"}
    assert not (dangerous & ALLOWED_COMMANDS)


# ===========================================================================
# SystemInfo: is_root, hostname, os_description
# ===========================================================================

@linux_only
def test_is_root_matches_effective_uid(sysinfo):
    assert sysinfo.is_root() == (os.geteuid() == 0)


def test_hostname_matches_socket(sysinfo):
    assert sysinfo.hostname() == socket.gethostname()


def test_os_description_is_a_non_empty_string(sysinfo):
    description = sysinfo.os_description()

    assert isinstance(description, str)
    assert description.strip()


def test_parse_pretty_name_with_double_quotes():
    text = 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\n'
    assert _parse_pretty_name(text) == "Ubuntu 22.04.4 LTS"


def test_parse_pretty_name_without_quotes():
    assert _parse_pretty_name("PRETTY_NAME=Debian\n") == "Debian"


def test_parse_pretty_name_missing_returns_none():
    assert _parse_pretty_name("NAME=Ubuntu\nID=ubuntu\n") is None


# ===========================================================================
# SystemInfo: find_files
# ===========================================================================

@pytest.fixture
def tree(tmp_path):
    """A small directory tree with known permissions."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "wwdir").mkdir()

    files = {
        "normal.txt": 0o644,
        "ww.txt": 0o666,
        "suid_bin": 0o4755,
        "sub/ww2.txt": 0o666,
    }
    for name, mode in files.items():
        path = tmp_path / name
        path.write_text("x")
        path.chmod(mode)

    (tmp_path / "wwdir").chmod(0o777)
    os.symlink(tmp_path / "ww.txt", tmp_path / "link_to_ww")
    return tmp_path


@linux_only
def test_find_world_writable_files(sysinfo, tree):
    result = sysinfo.find_files([str(tree)], FindPredicate.WORLD_WRITABLE)

    assert result.paths == sorted([str(tree / "ww.txt"), str(tree / "sub" / "ww2.txt")])
    assert result.unreadable_count == 0


@linux_only
def test_find_ignores_symlinks_and_directories(sysinfo, tree):
    result = sysinfo.find_files([str(tree)], FindPredicate.WORLD_WRITABLE)

    assert str(tree / "link_to_ww") not in result.paths
    assert str(tree / "wwdir") not in result.paths


@linux_only
def test_find_suid_files(sysinfo, tree):
    result = sysinfo.find_files([str(tree)], FindPredicate.SUID_SGID)

    assert result.paths == [str(tree / "suid_bin")]


@linux_only
def test_find_does_not_return_duplicates_for_overlapping_roots(sysinfo, tree):
    result = sysinfo.find_files([str(tree), str(tree / "sub")], FindPredicate.WORLD_WRITABLE)

    assert len(result.paths) == len(set(result.paths))


def test_find_missing_root_is_counted_as_unreadable(sysinfo, tmp_path):
    result = sysinfo.find_files([str(tmp_path / "missing")], FindPredicate.SUID_SGID)

    assert result.paths == []
    assert result.unreadable_count == 1


@linux_only
@skip_if_root
def test_find_counts_unreadable_directories(sysinfo, tree):
    locked = tree / "locked"
    locked.mkdir()
    locked.chmod(0o000)
    try:
        result = sysinfo.find_files([str(tree)], FindPredicate.WORLD_WRITABLE)
    finally:
        locked.chmod(0o700)  # so pytest can clean up

    assert result.unreadable_count >= 1
    assert str(tree / "ww.txt") in result.paths  # the rest of the scan still worked


def test_find_rejects_invalid_predicate(sysinfo, tmp_path):
    with pytest.raises(ValueError):
        sysinfo.find_files([str(tmp_path)], "SUID_SGID")


# ===========================================================================
# Read-only audit of the source code
# ===========================================================================

FORBIDDEN_OS_FUNCTIONS = {
    "remove", "unlink", "rmdir", "removedirs", "rename", "replace", "mkdir",
    "makedirs", "chmod", "chown", "system", "symlink", "link", "truncate",
    "utime", "popen", "kill", "killpg",
}
FORBIDDEN_METHODS = {
    "write_text", "write_bytes", "write", "writelines", "unlink", "rmdir",
    "mkdir", "touch",
}


@pytest.fixture(scope="module")
def system_ast():
    return ast.parse(Path(system.__file__).read_text(encoding="utf-8"))


def test_source_never_opens_files_for_writing(system_ast):
    for node in ast.walk(system_ast):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            mode = None
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                    mode = keyword.value.value
            assert mode == "r", f"open() at line {node.lineno} must use mode 'r'"


def test_source_never_uses_a_shell(system_ast):
    for node in ast.walk(system_ast):
        if isinstance(node, ast.keyword):
            assert node.arg != "shell", "no subprocess call may pass a shell argument"


def test_source_never_calls_modifying_functions(system_ast):
    for node in ast.walk(system_ast):
        if isinstance(node, ast.Attribute):
            is_os_call = isinstance(node.value, ast.Name) and node.value.id == "os"
            assert not (is_os_call and node.attr in FORBIDDEN_OS_FUNCTIONS), (
                f"os.{node.attr} at line {node.lineno} could modify the system"
            )
            assert node.attr not in FORBIDDEN_METHODS, (
                f".{node.attr} at line {node.lineno} could modify the system"
            )


def test_source_does_not_import_shutil(system_ast):
    for node in ast.walk(system_ast):
        if isinstance(node, ast.Import):
            assert "shutil" not in [alias.name for alias in node.names]
        if isinstance(node, ast.ImportFrom):
            assert node.module != "shutil"


# ===========================================================================
# FakeSystemInfo
# ===========================================================================

def test_fake_defaults():
    fake = FakeSystemInfo()

    assert fake.is_root() is False
    assert fake.hostname() == "fake-host"
    assert fake.os_description() == "Fake Linux 1.0"


def test_fake_custom_metadata():
    fake = FakeSystemInfo(root=True, hostname="lab-vm", os_description="Ubuntu 22.04 LTS")

    assert fake.is_root() is True
    assert fake.hostname() == "lab-vm"
    assert fake.os_description() == "Ubuntu 22.04 LTS"


def test_fake_serves_configured_file():
    fake = FakeSystemInfo()
    fake.add_file("/etc/ssh/sshd_config", "PermitRootLogin yes\n")

    result = fake.read_file("/etc/ssh/sshd_config")

    assert result.ok
    assert "PermitRootLogin yes" in result.text


def test_fake_unknown_file_is_not_found():
    result = FakeSystemInfo().read_file("/etc/does-not-exist")

    assert result.error == ErrorKind.NOT_FOUND


def test_fake_simulates_file_permission_denied():
    fake = FakeSystemInfo()
    fake.add_file_error("/etc/shadow", ErrorKind.PERMISSION_DENIED)

    result = fake.read_file("/etc/shadow")

    assert not result.ok
    assert result.error == ErrorKind.PERMISSION_DENIED
    assert result.detail  # has a default explanation


def test_fake_directory_listing_and_errors():
    fake = FakeSystemInfo()
    fake.add_dir("/etc/sudoers.d", ["90-extra", "10-admin"])
    fake.add_dir_error("/root", ErrorKind.PERMISSION_DENIED)

    assert fake.list_dir("/etc/sudoers.d").entries == ["10-admin", "90-extra"]
    assert fake.list_dir("/root").error == ErrorKind.PERMISSION_DENIED
    assert fake.list_dir("/nowhere").error == ErrorKind.NOT_FOUND


def test_fake_stat_with_defaults_and_overrides():
    fake = FakeSystemInfo()
    fake.add_stat("/etc/passwd", 0o644)
    fake.add_stat("/etc/shadow", 0o640, group="shadow", gid=42)
    fake.add_stat("/home/alice", 0o750, owner="alice", uid=1000, is_dir=True)

    passwd = fake.stat_path("/etc/passwd")
    assert passwd.ok and passwd.mode == 0o644
    assert passwd.owner == "root" and passwd.is_file

    shadow = fake.stat_path("/etc/shadow")
    assert shadow.group == "shadow" and shadow.gid == 42

    home = fake.stat_path("/home/alice")
    assert home.is_dir and not home.is_file and home.uid == 1000


def test_fake_stat_unknown_path_and_error():
    fake = FakeSystemInfo()
    fake.add_stat_error("/etc/shadow", ErrorKind.PERMISSION_DENIED)

    assert fake.stat_path("/etc/shadow").error == ErrorKind.PERMISSION_DENIED
    assert fake.stat_path("/unknown").error == ErrorKind.NOT_FOUND


def test_fake_serves_configured_command():
    fake = FakeSystemInfo()
    fake.add_command(["sshd", "-T"], stdout="permitrootlogin yes\n")
    fake.add_command(["ufw", "status"], stderr="denied", returncode=1)

    sshd = fake.run_command(["sshd", "-T"])
    assert sshd.ok and sshd.stdout == "permitrootlogin yes\n"

    ufw = fake.run_command(["ufw", "status"])
    assert ufw.ok and ufw.returncode == 1 and ufw.stderr == "denied"


def test_fake_unconfigured_command_is_tool_not_found():
    result = FakeSystemInfo().run_command(["ufw", "status"])

    assert result.error == ErrorKind.TOOL_NOT_FOUND


def test_fake_simulates_command_errors():
    fake = FakeSystemInfo()
    fake.add_command_error(["iptables", "-S"], ErrorKind.PERMISSION_DENIED)
    fake.add_command_error(["apt", "list", "--upgradable"], ErrorKind.TIMEOUT)

    assert fake.run_command(["iptables", "-S"]).error == ErrorKind.PERMISSION_DENIED
    assert fake.run_command(["apt", "list", "--upgradable"]).error == ErrorKind.TIMEOUT


def test_fake_enforces_the_same_command_rules_as_the_real_class():
    fake = FakeSystemInfo()

    with pytest.raises(ValueError):
        fake.run_command("ss -tulnp")
    with pytest.raises(ValueError):
        fake.run_command(["rm", "-rf", "/"])


def test_fake_find_files_by_predicate():
    fake = FakeSystemInfo()
    fake.add_found_files(FindPredicate.SUID_SGID, ["/usr/bin/sudo", "/usr/bin/find"], unreadable_count=2)

    suid = fake.find_files(["/usr"], FindPredicate.SUID_SGID)
    assert suid.paths == ["/usr/bin/find", "/usr/bin/sudo"]
    assert suid.unreadable_count == 2

    # A predicate nobody configured finds nothing.
    assert fake.find_files(["/etc"], FindPredicate.WORLD_WRITABLE).paths == []


def test_fake_find_files_rejects_invalid_predicate():
    with pytest.raises(ValueError):
        FakeSystemInfo().find_files(["/etc"], "SUID_SGID")


def test_fake_has_the_same_public_methods_as_the_real_class():
    real_methods = {
        name for name, member in inspect.getmembers(SystemInfo, inspect.isfunction)
        if not name.startswith("_")
    }

    assert real_methods  # sanity check: we found something to compare

    for name in real_methods:
        assert hasattr(FakeSystemInfo, name), f"FakeSystemInfo is missing {name}()"
        real_params = list(inspect.signature(getattr(SystemInfo, name)).parameters)
        fake_params = list(inspect.signature(getattr(FakeSystemInfo, name)).parameters)
        assert real_params == fake_params, f"{name}() signatures differ"
