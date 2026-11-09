import datetime as dt
import fcntl
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("retention", ROOT / "tools/audit-retention.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
NOW = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)


class Retention(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = pathlib.Path(self.temp.name)
        self.db = self.write("porter.db", b"session state")
        self.journal = self.write("porter-audit.jsonl", b"SECRET audit content\n")

    def write(self, name, content):
        path = self.dir / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_dry_run_and_offline_rotation_preserve_private_data(self):
        old = self.write("porter-audit.jsonl.20200101T000000000000Z", b"old")
        unrelated = self.write("unrelated.jsonl.20200101T000000000000Z", b"unrelated")
        recent = self.write("porter-audit.jsonl.20261110T000000000000Z", b"recent")
        os.utime(recent, (0, 0))  # Retention uses archive time, not modified time.
        result = r.maintain(self.dir, rotate=True, now=NOW + dt.timedelta(seconds=1))
        self.assertFalse(result["applied"])
        self.assertTrue(old.exists())
        with self.assertRaises(r.UnsafeDestination):
            r.maintain(self.dir, rotate=True, apply=True)
        r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW + dt.timedelta(seconds=1))
        self.assertFalse(old.exists())
        self.assertTrue(recent.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(self.db.read_bytes(), b"session state")
        self.assertEqual(self.journal.read_bytes(), b"")
        archived = self.dir / "porter-audit.jsonl.20261110T000001000000Z"
        self.assertEqual(archived.read_bytes(), b"SECRET audit content\n")
        for path in (self.journal, archived):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_uid, archived.stat().st_uid)

    def test_unsafe_destinations_and_archive_aliases(self):
        for mode in (0o644, 0o666):
            self.journal.chmod(mode)
            with self.assertRaises(r.UnsafeDestination):
                r.maintain(self.dir)
        self.journal.unlink()
        self.journal.symlink_to(self.db)
        with self.assertRaises(r.UnsafeDestination):
            r.maintain(self.dir)
        self.journal.unlink()
        os.link(self.db, self.journal)
        with self.assertRaises(r.UnsafeDestination):
            r.maintain(self.dir)
        self.journal.unlink()
        self.write("porter-audit.jsonl", b"audit")
        alias = self.dir / "porter-audit.jsonl.20200101T000000000000Z"
        os.link(self.db, alias)
        with self.assertRaises(r.UnsafeDestination):
            r.maintain(self.dir, apply=True, stopped=True, now=NOW)
        self.assertEqual(self.db.read_bytes(), b"session state")

    def test_collision_and_invalid_options_do_not_overwrite(self):
        collision = self.write("porter-audit.jsonl.20261110T000000000000Z", b"keep")
        with self.assertRaises(FileExistsError):
            r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW)
        self.assertEqual(collision.read_bytes(), b"keep")
        self.assertEqual(self.journal.read_bytes(), b"SECRET audit content\n")
        for kwargs in ({"journal": "../porter.db"}, {"days": 0}, {"database": "porter-audit.jsonl"}):
            with self.assertRaises(r.UnsafeDestination):
                r.maintain(self.dir, **kwargs)

    def test_failed_new_file_ownership_restores_original(self):
        with mock.patch.object(r.os, "fchown", side_effect=PermissionError("SECRET failure")):
            with self.assertRaises(PermissionError):
                r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW)
        self.assertEqual(self.journal.read_bytes(), b"SECRET audit content\n")
        self.assertEqual(self.db.read_bytes(), b"session state")
        self.assertFalse((self.dir / "porter-audit.jsonl.20261110T000000000000Z").exists())

    def test_live_database_lock_prevents_all_mutations(self):
        old = self.write("porter-audit.jsonl.20200101T000000000000Z", b"old")
        with self.db.open("rb") as live:
            fcntl.flock(live, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Dry runs remain useful while Porter is running.
            r.maintain(self.dir, rotate=True, now=NOW)
            with self.assertRaises(BlockingIOError):
                r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW)
            self.assertEqual(self.journal.read_bytes(), b"SECRET audit content\n")
            self.assertEqual(old.read_bytes(), b"old")
        r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW)
        self.assertFalse(old.exists())

    def test_database_lock_is_held_during_rotation(self):
        link = r.os.link
        def checked_link(*args, **kwargs):
            with self.db.open("rb") as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return link(*args, **kwargs)
        with mock.patch.object(r.os, "link", side_effect=checked_link):
            r.maintain(self.dir, rotate=True, apply=True, stopped=True, now=NOW)
        with self.db.open("rb") as after:
            fcntl.flock(after, fcntl.LOCK_EX | fcntl.LOCK_NB)
