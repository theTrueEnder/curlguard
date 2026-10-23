"""Private staging and atomic, no-clobber publication for explicit artifacts."""

import os
import shutil
import uuid
from pathlib import Path


def publish_new(source, destination):
    destination = Path(destination).absolute()
    parent = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    directory = ".curlguard-publish-" + uuid.uuid4().hex
    private = None
    created = False
    try:
        # Hold directory descriptors throughout publication. Another user with
        # access to the destination's parent cannot substitute the staged inode.
        os.mkdir(directory, mode=0o700, dir_fd=parent)
        created = True
        private = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
        )
        fd = os.open(
            "payload", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=private
        )
        with os.fdopen(fd, "wb") as out, Path(source).open("rb") as data:
            shutil.copyfileobj(data, out)
            out.flush()
            os.fsync(out.fileno())
        # link() atomically fails for any existing name, including a dangling symlink.
        os.link(
            "payload",
            destination.name,
            src_dir_fd=private,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
    finally:
        try:
            if private is not None:
                try:
                    os.unlink("payload", dir_fd=private)
                finally:
                    os.close(private)
            if created:
                os.rmdir(directory, dir_fd=parent)
        finally:
            os.close(parent)
