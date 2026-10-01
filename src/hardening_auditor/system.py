"""System-information layer for the Linux Security Hardening Auditor.

SystemInfo is the ONLY place in the project that talks to the operating
system. Security checks ask SystemInfo for data and analyse the answer;
they never call open(), subprocess, or os functions themselves.

Read-only guarantee
-------------------
* Files are opened only in read mode.
* Nothing here creates, modifies, renames, or deletes anything.
* Commands run as argument lists (never through a shell) and only if the
  executable is on the ALLOWED_COMMANDS list. The list limits WHICH programs
  can run; checks are responsible for using only read-only subcommands
  (for example `systemctl is-active`, never `systemctl stop`).
* find_files() accepts a named predicate, not an arbitrary function.

Error handling
--------------
Expected OS problems (missing file, permission denied, tool not installed,
timeout) are returned as values with an ErrorKind, so a check can turn them
into a NOT_ASSESSED finding. Misuse by the caller (a shell string, a command
that is not allowed) raises ValueError, because it is a bug, not a property
of the machine being audited.

SystemInfo targets Linux: it relies on Unix-only features (pwd, grp,
geteuid, POSIX permission bits). The module can still be imported on other
systems so that FakeSystemInfo and the result types are usable in tests,
but the real SystemInfo methods are only supported on Linux.
FakeSystemInfo, at the bottom, never touches the OS and is meant for tests.
"""

import os
import platform
import socket
import stat
import subprocess
from dataclasses import dataclass, field
from enum import Enum

DEFAULT_TIMEOUT = 10  # seconds

# Executables the auditor may run. Add to this list deliberately.
ALLOWED_COMMANDS = frozenset({
    "sshd",
    "ss",
    "ufw",
    "nft",
    "iptables",
    "systemctl",
    "dpkg",
    "dpkg-query",
    "apt",
})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ErrorKind(Enum):
    """Why a request to the system could not be completed."""

    NOT_FOUND = "NOT_FOUND"                  # file or directory does not exist
    PERMISSION_DENIED = "PERMISSION_DENIED"  # not allowed to read / execute
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"        # command is not installed
    TIMEOUT = "TIMEOUT"                      # command ran too long
    UNEXPECTED = "UNEXPECTED"                # any other OS error


class FindPredicate(Enum):
    """The only file searches find_files() can perform."""

    WORLD_WRITABLE = "WORLD_WRITABLE"  # regular files writable by "other"
    SUID_SGID = "SUID_SGID"            # regular files with setuid or setgid bit


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class _ResultMixin:
    """Gives a result an `ok` property: True when there is no error."""

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class FileResult(_ResultMixin):
    text: str = ""
    error: ErrorKind | None = None
    detail: str = ""


@dataclass(frozen=True)
class DirResult(_ResultMixin):
    entries: list[str] = field(default_factory=list)  # names, not full paths
    error: ErrorKind | None = None
    detail: str = ""


@dataclass(frozen=True)
class StatResult(_ResultMixin):
    mode: int = 0  # permission bits incl. setuid/setgid/sticky, e.g. 0o640
    uid: int = 0
    gid: int = 0
    owner: str = ""
    group: str = ""
    is_dir: bool = False
    is_file: bool = False
    error: ErrorKind | None = None
    detail: str = ""


@dataclass(frozen=True)
class CommandResult(_ResultMixin):
    """`ok` means the command ran. A non-zero returncode is still ok."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: ErrorKind | None = None
    detail: str = ""


@dataclass(frozen=True)
class FindResult:
    """Matching file paths, plus how many paths could not be inspected."""

    paths: list[str] = field(default_factory=list)
    unreadable_count: int = 0


# ---------------------------------------------------------------------------
# Helpers shared by SystemInfo and FakeSystemInfo
# ---------------------------------------------------------------------------

def _error_kind(exc: OSError) -> ErrorKind:
    """Translate a Python OSError into one of our ErrorKinds."""
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return ErrorKind.NOT_FOUND
    if isinstance(exc, PermissionError):
        return ErrorKind.PERMISSION_DENIED
    return ErrorKind.UNEXPECTED


def _validate_command(args) -> None:
    """Reject shell strings and executables that are not allowed."""
    if not isinstance(args, (list, tuple)) or not args:
        raise ValueError("args must be a non-empty list of strings, not a shell string")
    if not all(isinstance(arg, str) for arg in args):
        raise ValueError("every command argument must be a string")
    name = os.path.basename(args[0])
    if name not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowed: {name!r}")


def _command_env() -> dict[str, str]:
    """Environment for child processes: stable output, and sbin dirs on PATH."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"  # untranslated, predictable output for parsing
    path_dirs = env.get("PATH", "/usr/bin:/bin").split(os.pathsep)
    for extra in ("/usr/sbin", "/sbin"):  # sshd, ufw, iptables live here
        if extra not in path_dirs:
            path_dirs.append(extra)
    env["PATH"] = os.pathsep.join(path_dirs)
    return env


def _owner_name(uid: int) -> str:
    import pwd  # Unix-only; imported here so the module imports on any OS
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group_name(gid: int) -> str:
    import grp  # Unix-only; imported here so the module imports on any OS
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def _same_device(path: str, device: int) -> bool:
    """True if path is on the given device (or cannot be checked)."""
    try:
        return os.lstat(path).st_dev == device
    except OSError:
        return True  # the directory walk will count it as unreadable


def _matches(predicate: FindPredicate, mode: int) -> bool:
    if predicate == FindPredicate.WORLD_WRITABLE:
        return bool(mode & stat.S_IWOTH)
    return bool(mode & (stat.S_ISUID | stat.S_ISGID))  # SUID_SGID


def _parse_pretty_name(os_release_text: str) -> str | None:
    """Extract PRETTY_NAME from the text of /etc/os-release."""
    for line in os_release_text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "PRETTY_NAME":
            return value.strip().strip('"').strip("'") or None
    return None


# ---------------------------------------------------------------------------
# The real implementation
# ---------------------------------------------------------------------------

class SystemInfo:
    """Read-only access to the machine being audited."""

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def hostname(self) -> str:
        return socket.gethostname()

    def os_description(self) -> str:
        """e.g. 'Ubuntu 22.04.4 LTS', falling back to a generic description."""
        result = self.read_file("/etc/os-release")
        if result.ok:
            name = _parse_pretty_name(result.text)
            if name:
                return name
        return f"{platform.system()} {platform.release()}".strip()

    def read_file(self, path: str) -> FileResult:
        """Read a text file. Undecodable bytes are replaced, not fatal."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return FileResult(text=handle.read())
        except OSError as exc:
            return FileResult(error=_error_kind(exc), detail=str(exc))

    def list_dir(self, path: str) -> DirResult:
        """List the names inside a directory (sorted)."""
        try:
            return DirResult(entries=sorted(os.listdir(path)))
        except OSError as exc:
            return DirResult(error=_error_kind(exc), detail=str(exc))

    def stat_path(self, path: str) -> StatResult:
        """Mode, owner, and group of a path (symlinks are followed)."""
        try:
            info = os.stat(path)
        except OSError as exc:
            return StatResult(error=_error_kind(exc), detail=str(exc))
        return StatResult(
            mode=stat.S_IMODE(info.st_mode),
            uid=info.st_uid,
            gid=info.st_gid,
            owner=_owner_name(info.st_uid),
            group=_group_name(info.st_gid),
            is_dir=stat.S_ISDIR(info.st_mode),
            is_file=stat.S_ISREG(info.st_mode),
        )

    def run_command(self, args: list[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        """Run an allowed command (argument list, no shell) and capture output."""
        _validate_command(args)
        try:
            completed = subprocess.run(
                list(args),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                env=_command_env(),
                check=False,
            )
        except FileNotFoundError as exc:
            return CommandResult(error=ErrorKind.TOOL_NOT_FOUND, detail=str(exc))
        except PermissionError as exc:
            return CommandResult(error=ErrorKind.PERMISSION_DENIED, detail=str(exc))
        except subprocess.TimeoutExpired:
            return CommandResult(
                error=ErrorKind.TIMEOUT, detail=f"timed out after {timeout} seconds"
            )
        except OSError as exc:
            return CommandResult(error=ErrorKind.UNEXPECTED, detail=str(exc))
        return CommandResult(
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )

    def find_files(self, roots: list[str], predicate: FindPredicate) -> FindResult:
        """Find regular files under roots that match a named predicate.

        Symlinks are not followed and other filesystems are not entered.
        Directories or roots that cannot be inspected are counted in
        unreadable_count instead of raising.
        """
        if not isinstance(predicate, FindPredicate):
            raise ValueError("predicate must be a FindPredicate")

        found: set[str] = set()  # a set, because /bin and /usr/bin can overlap
        unreadable = 0

        def on_walk_error(_exc: OSError) -> None:
            nonlocal unreadable
            unreadable += 1

        for root in roots:
            try:
                root_device = os.stat(root).st_dev
            except OSError:
                unreadable += 1
                continue

            for dirpath, dirnames, filenames in os.walk(
                root, onerror=on_walk_error, followlinks=False
            ):
                # Editing dirnames in place stops the walk from entering
                # directories that live on a different filesystem.
                dirnames[:] = [
                    d for d in dirnames
                    if _same_device(os.path.join(dirpath, d), root_device)
                ]
                for name in filenames:
                    full_path = os.path.join(dirpath, name)
                    try:
                        info = os.lstat(full_path)
                    except OSError:
                        unreadable += 1
                        continue
                    if stat.S_ISREG(info.st_mode) and _matches(predicate, info.st_mode):
                        found.add(full_path)

        return FindResult(paths=sorted(found), unreadable_count=unreadable)


# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------

class FakeSystemInfo:
    """A SystemInfo that serves canned data and never touches the OS.

    Nothing exists until a test adds it, so by default:
    files, directories, and stat requests return NOT_FOUND, commands return
    TOOL_NOT_FOUND, and find_files returns no matches.

    Example:
        fake = FakeSystemInfo(root=True)
        fake.add_file("/etc/ssh/sshd_config", "PermitRootLogin yes\\n")
        fake.add_command(["sshd", "-T"], stdout="permitrootlogin yes\\n")
    """

    def __init__(
        self,
        *,
        root: bool = False,
        hostname: str = "fake-host",
        os_description: str = "Fake Linux 1.0",
    ):
        self._root = root
        self._hostname = hostname
        self._os_description = os_description
        self._files: dict[str, FileResult] = {}
        self._dirs: dict[str, DirResult] = {}
        self._stats: dict[str, StatResult] = {}
        self._commands: dict[tuple[str, ...], CommandResult] = {}
        self._found: dict[FindPredicate, FindResult] = {}

    # --- configuring the fake (used by tests) -----------------------------

    def add_file(self, path: str, text: str) -> None:
        self._files[path] = FileResult(text=text)

    def add_file_error(self, path: str, error: ErrorKind, detail: str = "") -> None:
        self._files[path] = FileResult(error=error, detail=detail or f"simulated {error.value}")

    def add_dir(self, path: str, entries: list[str]) -> None:
        self._dirs[path] = DirResult(entries=sorted(entries))

    def add_dir_error(self, path: str, error: ErrorKind, detail: str = "") -> None:
        self._dirs[path] = DirResult(error=error, detail=detail or f"simulated {error.value}")

    def add_stat(
        self,
        path: str,
        mode: int,
        owner: str = "root",
        group: str = "root",
        uid: int = 0,
        gid: int = 0,
        is_dir: bool = False,
    ) -> None:
        self._stats[path] = StatResult(
            mode=mode,
            uid=uid,
            gid=gid,
            owner=owner,
            group=group,
            is_dir=is_dir,
            is_file=not is_dir,
        )

    def add_stat_error(self, path: str, error: ErrorKind, detail: str = "") -> None:
        self._stats[path] = StatResult(error=error, detail=detail or f"simulated {error.value}")

    def add_command(
        self, args: list[str], stdout: str = "", stderr: str = "", returncode: int = 0
    ) -> None:
        self._commands[tuple(args)] = CommandResult(
            stdout=stdout, stderr=stderr, returncode=returncode
        )

    def add_command_error(self, args: list[str], error: ErrorKind, detail: str = "") -> None:
        self._commands[tuple(args)] = CommandResult(
            error=error, detail=detail or f"simulated {error.value}"
        )

    def add_found_files(
        self, predicate: FindPredicate, paths: list[str], unreadable_count: int = 0
    ) -> None:
        """Set the result for a predicate. The roots passed to find_files are ignored."""
        self._found[predicate] = FindResult(paths=sorted(paths), unreadable_count=unreadable_count)

    # --- same public interface as SystemInfo ------------------------------

    def is_root(self) -> bool:
        return self._root

    def hostname(self) -> str:
        return self._hostname

    def os_description(self) -> str:
        return self._os_description

    def read_file(self, path: str) -> FileResult:
        return self._files.get(
            path, FileResult(error=ErrorKind.NOT_FOUND, detail=f"no such file: {path}")
        )

    def list_dir(self, path: str) -> DirResult:
        return self._dirs.get(
            path, DirResult(error=ErrorKind.NOT_FOUND, detail=f"no such directory: {path}")
        )

    def stat_path(self, path: str) -> StatResult:
        return self._stats.get(
            path, StatResult(error=ErrorKind.NOT_FOUND, detail=f"no such path: {path}")
        )

    def run_command(self, args: list[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        _validate_command(args)  # same rules as the real class
        return self._commands.get(
            tuple(args),
            CommandResult(error=ErrorKind.TOOL_NOT_FOUND, detail=f"command not configured: {args[0]}"),
        )

    def find_files(self, roots: list[str], predicate: FindPredicate) -> FindResult:
        if not isinstance(predicate, FindPredicate):
            raise ValueError("predicate must be a FindPredicate")
        return self._found.get(predicate, FindResult())
