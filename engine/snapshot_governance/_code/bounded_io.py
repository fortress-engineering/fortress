"""Operational byte and JSON admission; no semantic or authorization decisions."""
import hashlib
import json
import math
import os
from pathlib import Path
import stat

MAX_BYTES = 512 * 1024 * 1024


def inventory(root, excluded, *, max_entries=200_000, max_files=100_000,
              max_path_bytes=32 * 1024 * 1024, max_depth=128):
    """Bound complete ordinary inventory before retaining directory entries."""
    root = Path(root)
    names = []
    entries = paths = 0
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
            raise OSError("UNSAFE_PATH: ordinary directory required")
        if depth >= max_depth:
            raise OSError("RESOURCE_LIMIT: inventory depth")
        children = []
        folded = set()
        with os.scandir(directory) as scan:
            for entry in scan:
                entries += 1
                if entries > max_entries:
                    raise OSError("RESOURCE_LIMIT: inventory entries")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                paths += len(relative.encode("utf-8", errors="strict"))
                if paths > max_path_bytes:
                    raise OSError("RESOURCE_LIMIT: inventory path bytes")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise OSError("UNSAFE_PATH: linked inventory entry")
                if any(relative == prefix or relative.startswith(prefix + "/") for prefix in excluded):
                    continue
                if entry.name.lower() in folded:
                    raise OSError("UNSAFE_PATH: ambiguous case-folded inventory")
                folded.add(entry.name.lower())
                if stat.S_ISDIR(info.st_mode):
                    children.append((path, depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    if len(names) >= max_files:
                        raise OSError("RESOURCE_LIMIT: inventory files")
                    names.append(relative)
                else:
                    raise OSError("UNSAFE_PATH: nonordinary inventory entry")
        after = directory.lstat()
        if not os.path.samestat(before, after) or before.st_mtime_ns != after.st_mtime_ns:
            raise OSError("SOURCE_DRIFT: inventory directory changed")
        pending.extend(sorted(children, reverse=True))
    return sorted(names)


def _ordinary(info):
    return stat.S_ISREG(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400


def _consume_ordinary(path, maximum, consume):
    """Share native admission and drift checks across bounded consumers."""
    path = Path(path)
    before = path.lstat()
    if not _ordinary(before) or before.st_size > maximum:
        raise OSError("UNSAFE_PATH or RESOURCE_LIMIT: ordinary bounded input required")
    for parent in path.absolute().parents:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OSError("UNSAFE_PATH: linked input ancestor")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not _ordinary(opened) or not os.path.samestat(before, opened) or opened.st_size > maximum:
            raise OSError("SOURCE_DRIFT: input changed during admission")
        length, result = consume(stream, min(maximum, opened.st_size))
        after = os.fstat(stream.fileno())
        named = path.lstat()
        if length > maximum or length != before.st_size or not _ordinary(named) or any(
            not os.path.samestat(before, info) or info.st_size != before.st_size or info.st_mtime_ns != before.st_mtime_ns
            for info in (opened, after, named)
        ):
            raise OSError("SOURCE_DRIFT or RESOURCE_LIMIT: unstable input")
        return result


def read_ordinary(path, maximum=MAX_BYTES):
    """Read bounded bytes from one retained ordinary file and recheck its identity."""
    def collect(stream, limit):
        data = stream.read(limit + 1)
        return len(data), data
    return _consume_ordinary(path, maximum, collect)


def _stream_ordinary(path, maximum, output, prefix_size=0):
    """Hash complete pinned bytes with at most 64 KiB of input scratch.

    This establishes integrity only. It neither parses evidence nor authenticates
    its producer, and changed or incomplete inputs never return a digest.
    """
    def collect(stream, limit):
        digest = hashlib.sha256()
        prefix = bytearray()
        length = 0
        remaining = limit + 1
        while remaining:
            chunk = stream.read(min(64 * 1024, remaining))
            if not chunk:
                break
            length += len(chunk)
            remaining -= len(chunk)
            if output is not None and output.write(chunk) != len(chunk):
                raise OSError("INCOMPLETE_WRITE: ordinary copy was not complete")
            digest.update(chunk)
            if len(prefix) < prefix_size:
                prefix.extend(chunk[:prefix_size - len(prefix)])
        return length, (length, "sha256:" + digest.hexdigest(), bytes(prefix))
    return _consume_ordinary(path, maximum, collect)


def hash_ordinary(path, maximum=MAX_BYTES):
    """Hash complete pinned bytes with bounded scratch and unchanged admission."""
    return _stream_ordinary(path, maximum, None)[:2]


def hash_ordinary_with_prefix(path, prefix_size, maximum=MAX_BYTES):
    """Return a bounded header from the same retained bytes that are hashed."""
    if type(prefix_size) is not int or not 1 <= prefix_size <= 1024:
        raise ValueError("prefix size must be between 1 and 1024 bytes")
    return _stream_ordinary(path, maximum, None, prefix_size)


def copy_ordinary(path, output, maximum=MAX_BYTES):
    """Transfer verified ordinary bytes to an explicitly owned caller stream.

    No destination path is opened here. A failed copy supplies no favorable
    integrity result; the caller owns partial-output recovery or publication.
    """
    return _stream_ordinary(path, maximum, output)[:2]


def strict_json(source, *, maximum=MAX_BYTES, nodes=16_000_000, depth=96):
    """Admit global allocation units before strict decoding; reject duplicates."""
    data = source.encode("utf-8") if isinstance(source, str) else source
    def invalid(message):
        return json.JSONDecodeError(message, "", 0)
    if len(data) > maximum:
        raise invalid("RESOURCE_LIMIT: JSON bytes")
    quoted = escaped = primitive = False
    count = level = 0
    for byte in data:
        if quoted:
            if not escaped and byte == 34:
                quoted = False
            escaped = not escaped and byte == 92
            continue
        if byte in (32, 9, 10, 13, 44, 58, 93, 125):
            primitive = False
            if byte in (93, 125):
                level = max(0, level - 1)
        elif byte in (91, 123):
            count += 1
            level += 1
            primitive = False
        elif byte == 34:
            quoted = True
            primitive = False
            count += 1
        elif not primitive:
            count += 1
            primitive = True
        if count > nodes or level > depth:
            raise invalid("RESOURCE_LIMIT: JSON nodes or depth")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise invalid("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise invalid("non-finite JSON constant")
    def finite(token):
        value = float(token)
        if not math.isfinite(value):
            raise invalid("non-finite JSON number")
        return value
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=finite)
