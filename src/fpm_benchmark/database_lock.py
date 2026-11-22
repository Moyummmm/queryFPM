"""Nonblocking database and output-directory locks for revised runs."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import stat


def _reserved_lock_name(path):
    return path.name in {".fpm-output.lock", ".fpm-experiment.lock"} or path.name.endswith(".run.lock")


def _output_namespace(database_root, output):
    """Validate paths before creating coordination files or result artifacts.

    Sidecars are derived from the requested basename, so resolve the parent
    directory without changing that basename. Directory symlink aliases are
    supported; final result/sidecar symlinks are not.
    """
    requested = Path(output).absolute()
    output = requested.parent.resolve() / requested.name
    for path in (requested.parent, output.parent):
        if any(part.endswith(".records") or part == "queries" for part in path.parts):
            raise ValueError("Run output cannot be inside a reserved result-artifact directory")
    artifacts = [output] + [output.with_suffix(suffix) for suffix in (
        ".manifest.json", ".records", ".summary.json", ".token_audit.jsonl", ".jsonl.partial")]
    namespace_lock = output.parent / ".fpm-output.lock"
    legacy_lock = output.with_name(output.name + ".run.lock")
    protected = [namespace_lock, legacy_lock]
    if database_root is not None:
        protected.append(database_root / ".fpm-experiment.lock")
    if output.parent.is_dir():
        protected.extend(output.parent.glob("*.run.lock"))
    resolved_locks = {path.resolve() for path in protected}
    for artifact in artifacts:
        if _reserved_lock_name(artifact) or _reserved_lock_name(artifact.resolve()):
            raise ValueError("Run output or sidecar uses a reserved coordination-lock path")
        if artifact.is_symlink():
            raise ValueError("Run output and sidecar final paths cannot be symbolic links")
        if artifact.resolve() in resolved_locks:
            raise ValueError("Run output or sidecar aliases a coordination-lock path")
        if artifact.exists():
            for lock in protected:
                if lock.exists() and artifact.samefile(lock):
                    raise ValueError("Run output or sidecar aliases a coordination-lock inode")
    return output, namespace_lock, legacy_lock


@contextmanager
def _exclusive_file(path, *, description):
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    unlock = None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Lock path must be a regular file")
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                def unlock():
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                def unlock():
                    fcntl.flock(fd, fcntl.LOCK_UN)
        except (BlockingIOError, OSError) as exc:
            raise RuntimeError(description + " is already in use or cannot be locked") from exc
        yield fd
    finally:
        try:
            if unlock is not None:
                unlock()
        finally:
            os.close(fd)
        # Do not unlink: another process may already have this inode open.
        # Kernel locks disappear when their owning handles/processes close.


@contextmanager
def run_lock(database, output):
    """Hold database lease before fingerprinting and preserve output isolation.

    DB and output-directory symlink aliases share their respective locks.
    Every output in one directory shares a namespace lock, including names
    that alias another run's sidecars. Different databases may run concurrently
    when their output directories are distinct. Retain the old per-file lock
    as well, without deleting or replacing any coordination inode.
    """
    root = Path(database).resolve() if database else None
    if root is not None and (not root.is_dir() or not (root / "codeql-database.yml").is_file()):
        raise ValueError("Run requires an actual CodeQL database directory")
    output, namespace_lock, legacy_lock = _output_namespace(root, output)
    with ExitStack() as stack:
        database_fd = None
        if root is not None:
            database_fd = stack.enter_context(_exclusive_file(
                root / ".fpm-experiment.lock", description="CodeQL database"))
        output.parent.mkdir(parents=True, exist_ok=True)
        stack.enter_context(_exclusive_file(namespace_lock, description="Run output directory"))
        stack.enter_context(_exclusive_file(legacy_lock,
                                           description="Run output"))
        yield database_fd
