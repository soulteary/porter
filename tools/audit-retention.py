#!/usr/bin/env python3
"""Offline, metadata-only audit retention. Dry run unless --apply --stopped."""
import argparse
import datetime as dt
import os
import re
import stat
import sys


class UnsafeDestination(Exception):
    pass


def private_regular(info):
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise UnsafeDestination("expected a private regular file")


def same(a, b):
    return (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)


def maintain(directory, journal="porter-audit.jsonl", database="porter.db", days=30,
             rotate=False, apply=False, stopped=False, now=None):
    if days < 1 or days > 36500 or journal in ("", ".", "..") or database in ("", ".", ".."):
        raise UnsafeDestination("invalid retention options")
    if os.path.basename(journal) != journal or os.path.basename(database) != database or journal == database:
        raise UnsafeDestination("journal and database require distinct basenames")
    if apply and not stopped:
        raise UnsafeDestination("stop Porter before applying retention; --stopped is an operator acknowledgement")
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=days)
    pattern = re.compile(re.escape(journal) + r"\.(\d{8}T\d{12}Z)$")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) & 0o077:
            raise UnsafeDestination("audit directory must be owner-only")
        db = os.stat(database, dir_fd=descriptor, follow_symlinks=False)
        active = os.stat(journal, dir_fd=descriptor, follow_symlinks=False)
        private_regular(db)
        private_regular(active)
        if same(db, active):
            raise UnsafeDestination("audit destination aliases database")
        expired = []
        for name in os.listdir(descriptor):
            match = pattern.fullmatch(name)
            if not match:
                continue
            try:
                created = dt.datetime.strptime(match[1], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=dt.timezone.utc)
            except ValueError:
                continue
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            private_regular(info)
            if same(info, db) or same(info, active) or info.st_uid != active.st_uid:
                raise UnsafeDestination("archive aliases active data or has a different owner")
            if created < cutoff:
                expired.append((name, info))
        archive = journal + "." + now.strftime("%Y%m%dT%H%M%S%fZ") if rotate else None
        if apply and rotate:
            # Never overwrite a colliding archive. All operations use the opened
            # owner-only directory; the database is never opened for writing.
            if not same(active, os.stat(journal, dir_fd=descriptor, follow_symlinks=False)):
                raise UnsafeDestination("journal changed during planning")
            os.link(journal, archive, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
            if not same(active, os.stat(archive, dir_fd=descriptor, follow_symlinks=False)):
                os.unlink(archive, dir_fd=descriptor)
                raise UnsafeDestination("journal changed during rotation")
            os.unlink(journal, dir_fd=descriptor)
            new = None
            try:
                new = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
                os.fchown(new, active.st_uid, active.st_gid)
                os.fchmod(new, 0o600)
            except OSError:
                if new is not None:
                    os.close(new)
                    new = None
                    os.unlink(journal, dir_fd=descriptor)
                # Restore only if no new writer has claimed the path. Keep the
                # archive intact if that restoration cannot be completed.
                os.link(archive, journal, src_dir_fd=descriptor, dst_dir_fd=descriptor, follow_symlinks=False)
                os.unlink(archive, dir_fd=descriptor)
                raise
            finally:
                if new is not None:
                    os.close(new)
        if apply:
            for name, planned in expired:
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not same(planned, current):
                    raise UnsafeDestination("archive changed during planning")
                os.unlink(name, dir_fd=descriptor)
        return {"applied": apply, "rotate": rotate, "expired_archives": len(expired)}
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--journal", default="porter-audit.jsonl")
    parser.add_argument("--database", default="porter.db")
    parser.add_argument("--keep-days", type=int, default=30)
    parser.add_argument("--rotate", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--stopped", action="store_true")
    args = parser.parse_args()
    try:
        result = maintain(args.directory, args.journal, args.database, args.keep_days,
                          args.rotate, args.apply, args.stopped)
    except (OSError, UnsafeDestination):
        print("audit retention failed; check stopped state, private paths, ownership and mount access", file=sys.stderr)
        return 1
    print(("applied" if result["applied"] else "dry run") +
          ": rotate=" + str(result["rotate"]).lower() +
          ", expired_archives=" + str(result["expired_archives"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
