"""Bounded unchanged regular snapshot; reject every symlink component."""

import os
import stat


def read_regular(path, limit):
    if (
        any(type(getattr(os, name, None)) is not int or getattr(os, name, 0) <= 0
               for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY"))
        or type(getattr(os, "supports_dir_fd", None)) not in (set, frozenset)
        or os.open not in os.supports_dir_fd
    ):
        raise ValueError("safe_open_unsupported")
    text = os.fspath(path)
    if (
        not isinstance(text, str)
        or not text
        or len(text) > 4096
        or "\0" in text
        or ".." in text.split(os.sep)
    ):
        raise ValueError("invalid_path")
    parts = os.path.abspath(text).split(os.sep)[1:]
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("regular_file_or_byte_budget")
            data = bytearray()
            while len(data) <= limit:
                block = os.read(descriptor, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(descriptor)
            if (
                len(data) > limit
                or len(data) != after.st_size
                or any(
                    getattr(before, field) != getattr(after, field)
                    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                )
            ):
                raise ValueError("changed_or_byte_budget")
            return bytes(data)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
