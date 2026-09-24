import shlex

from lanscanman.core import rsync

KH = "/cfg/known_hosts"


def _data(sender="127.0.0.1", receiver="127.0.0.1", **kw):
    d = dict(sender_ip=sender, receiver_ip=receiver, sender_user="alice",
             full_source="/home/alice/My Docs/", full_dest="/backup/",
             src_path="/home/alice/My Docs/", args=["-a", "--dry-run"])
    d.update(kw)
    return d


def test_local_to_local():
    cmd = rsync.build_command(_data(), known_hosts=KH)
    assert cmd[:2] == ["rsync", "--info=progress2,name"]
    assert cmd[2] == f"--rsh=ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={KH}"
    # argv form: paths with spaces are passed as single, unquoted args
    assert cmd[3:] == ["-a", "--dry-run", "/home/alice/My Docs/", "/backup/"]


def test_local_to_remote_uses_our_known_hosts():
    cmd = rsync.build_command(
        _data(receiver="192.168.50.5", full_dest="bob@192.168.50.5:/srv/"), known_hosts=KH)
    assert cmd[0] == "rsync"
    assert cmd[-1] == "bob@192.168.50.5:/srv/"
    assert f"UserKnownHostsFile={KH}" in cmd[2]


def test_remote_to_remote_runs_on_sender_with_agent_forwarding():
    data = _data(sender="192.168.50.4", receiver="192.168.50.5",
                 full_source="alice@192.168.50.4:/data/My Docs/",
                 src_path="/data/My Docs/", full_dest="bob@192.168.50.5:/srv/")
    cmd = rsync.build_command(data, known_hosts=KH)
    assert cmd[:2] == ["ssh", "-A"]
    assert cmd[-2] == "alice@192.168.50.4"
    # The remote script is one argument: bash -lc '<rsync ...>'
    remote = shlex.split(cmd[-1])
    assert remote[:2] == ["bash", "-lc"]
    inner = shlex.split(remote[2])
    assert inner == ["rsync", "--info=progress2,name", "-a", "--dry-run",
                     "/data/My Docs/", "bob@192.168.50.5:/srv/"]   # bare sender path, not user@host


def test_remote_to_remote_quotes_hostile_values():
    data = _data(sender="192.168.50.4", receiver="192.168.50.5", sender_user="a;id",
                 src_path="/x'; touch /tmp/pwned; '", full_dest="b@192.168.50.5:/y")
    cmd = rsync.build_command(data, known_hosts=KH)
    assert cmd[-2] == "'a;id'@192.168.50.4"
    inner = shlex.split(shlex.split(cmd[-1])[2])
    assert inner[-2] == "/x'; touch /tmp/pwned; '"      # survives as one literal arg


def test_is_remote_to_remote():
    assert not rsync.is_remote_to_remote(_data())
    assert not rsync.is_remote_to_remote(_data(receiver="192.168.50.5"))
    assert rsync.is_remote_to_remote(_data(sender="192.168.50.4", receiver="192.168.50.5"))


def test_parse_progress():
    p = rsync.parse_progress("    536,870,912  50%   45.20MB/s    0:00:11 (xfr#3, to-chk=7/12)")
    assert (p.transferred, p.percent, p.speed, p.eta) == (536870912, 50, "45.20MB/s", "0:00:11")
    assert p.total_estimate == 1073741824
    assert p.size_display == "512.0 MB / 1.0 GB"


def test_parse_progress_zero_percent():
    p = rsync.parse_progress("          1,024   0%    0.00kB/s    0:00:00")
    assert p.total_estimate == 1024
    assert p.size_display == "1.0 KB"


def test_non_progress_lines():
    assert rsync.parse_progress("sending incremental file list") is None
    assert rsync.parse_progress("docs/report.pdf") is None


def test_split_output_handles_carriage_returns():
    lines, rest = rsync.split_output("file1\n  10  5% 1MB/s 0:01\r  20 10% 1MB/s 0:01\rpart")
    assert lines == ["file1", "  10  5% 1MB/s 0:01", "  20 10% 1MB/s 0:01"]
    assert rest == "part"
