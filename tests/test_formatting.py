import pytest

from lanscanman.core import formatting as f


@pytest.mark.parametrize("n, expected", [
    (None, "?"),
    (0, "0.0 B"),
    (1023, "1023.0 B"),
    (1024, "1.0 KB"),
    (1536, "1.5 KB"),
    (5 * 1024 ** 3, "5.0 GB"),
    (3 * 1024 ** 5, "3.0 PB"),
    ("1,048,576", "1.0 MB"),     # rsync prints commas
    ("garbage", "garbage"),
])
def test_fmt_bytes(n, expected):
    assert f.fmt_bytes(n) == expected


@pytest.mark.parametrize("mb, expected", [(None, "?"), (512, "512 MB"), (2048, "2.0 GB")])
def test_fmt_mb(mb, expected):
    assert f.fmt_mb(mb) == expected


@pytest.mark.parametrize("secs, expected", [
    (0, "0m"),
    (59, "0m"),
    (3600, "1h 0m"),
    (90061, "1d 1h 1m"),
    (86400 * 3 + 120, "3d 2m"),
])
def test_fmt_uptime(secs, expected):
    assert f.fmt_uptime(secs) == expected


@pytest.mark.parametrize("h, expected", [
    (None, "?"), (5, "5h"), (24, "1d 0h"), (100, "4d 4h"), (24 * 400, "1y 35d"),
])
def test_fmt_hours(h, expected):
    assert f.fmt_hours(h) == expected


@pytest.mark.parametrize("raw, expected", [
    ("0:00:05", "5s"),
    ("0:02:05", "2m 5s"),
    ("1:02:05", "1h 2m"),
    ("02:05", "2m 5s"),
    ("00:07", "7s"),
    ("soon", "soon"),
    ("1:2:3:4", "1:2:3:4"),
])
def test_fmt_eta(raw, expected):
    assert f.fmt_eta(raw) == expected


def test_fmt_speed_eta():
    assert f.fmt_speed_eta("", "") == "—"
    assert f.fmt_speed_eta("10MB/s", "") == "10MB/s"
    assert f.fmt_speed_eta("10MB/s", "0:01:00") == "10MB/s  ·  1m 0s"


@pytest.mark.parametrize("fn, low, mid, high", [
    (f.usage_color, 10, 70, 95),
    (f.disk_temp_color, 30, 45, 60),
    (f.hw_temp_color, 50, 75, 90),
    (f.wear_color, 10, 60, 90),
])
def test_thresholds(fn, low, mid, high):
    assert fn(None) == f.MUTED
    assert fn(low) == f.GOOD
    assert fn(mid) == f.WARN
    assert fn(high) == f.BAD


def test_bad_sector_color():
    assert f.bad_sector_color(None) == f.MUTED
    assert f.bad_sector_color(0) == f.GOOD
    assert f.bad_sector_color(1) == f.BAD
