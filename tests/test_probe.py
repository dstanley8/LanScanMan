import json

from lanscanman.core.probe import (
    BRANDS,
    calc_cpu_usage,
    detect_cpu_brand,
    detect_gpu_brand,
    parse_probe_output,
    split_sections,
)


def _probe(**sections):
    return "\n".join(f"###{k}###\n{v}" for k, v in sections.items())


def test_split_sections_handles_empty_and_preamble():
    raw = "motd noise\n###A###\n one \n###B###\n###C###\nx\ny\n"
    assert split_sections(raw) == {"A": "one", "B": "", "C": "x\ny"}


def test_calc_cpu_usage():
    s1 = "cpu  100 0 100 800 0 0 0 0 0 0"
    s2 = "cpu  150 0 150 900 0 0 0 0 0 0"   # 200 ticks, 100 idle
    assert calc_cpu_usage(s1, s2) == 50.0


def test_calc_cpu_usage_edge_cases():
    same = "cpu 1 2 3 4"
    assert calc_cpu_usage(same, same) == 0.0
    assert calc_cpu_usage("", "") is None
    assert calc_cpu_usage("cpu a b", "cpu c d") is None


NVIDIA_HOST = _probe(
    DISTRO="Ubuntu 24.04.1 LTS",
    CPU_MODEL="AMD Ryzen 7 5800X 8-Core Processor",
    CPU_CORES="16",
    STAT1="cpu  100 0 100 800 0 0 0 0 0 0",
    STAT2="cpu  150 0 150 900 0 0 0 0 0 0",
    MEM="MemTotal:       32768000 kB\nMemAvailable:   16384000 kB",
    UPTIME="93784.12 370000.00",
    CPU_TEMP="54875",
    AMD_GPU_BUSY="",
    NVIDIA="NVIDIA GeForce RTX 3080, 17, 1200, 10240, 48",
    LSPCI="0a:00.0 VGA compatible controller: NVIDIA Corporation GA102",
)


def test_parse_probe_nvidia_host():
    r = parse_probe_output(NVIDIA_HOST)
    assert r["distro"] == "Ubuntu 24.04.1 LTS"
    assert r["cpu_cores"] == 16
    assert r["cpu_usage"] == 50.0
    assert r["mem_total_kb"] == 32768000
    assert r["mem_avail_kb"] == 16384000
    assert r["cpu_temp_c"] == 55            # millidegrees rounded
    assert r["uptime_seconds"] == 93784.12
    assert r["gpu_name"] == "NVIDIA GeForce RTX 3080"   # nvidia-smi wins over lspci
    assert (r["gpu_usage"], r["gpu_mem_used_mb"], r["gpu_mem_total_mb"], r["gpu_temp_c"]) == (17, 1200, 10240, 48)


def test_parse_probe_amd_gpu_from_sysfs():
    raw = _probe(
        AMD_GPU_BUSY="42",
        AMD_GPU_MEM_USED=str(2 * 1024 ** 3),
        AMD_GPU_MEM_TOTAL=str(8 * 1024 ** 3),
        AMD_GPU_TEMP="61000",
        NVIDIA="",
        LSPCI="03:00.0 VGA compatible controller: Advanced Micro Devices, Inc. [AMD/ATI] Navi 22",
    )
    r = parse_probe_output(raw)
    assert r["gpu_usage"] == 42
    assert (r["gpu_mem_used_mb"], r["gpu_mem_total_mb"]) == (2048, 8192)
    assert r["gpu_temp_c"] == 61
    assert r["gpu_name"].startswith("Advanced Micro Devices")


def test_parse_probe_empty_output_is_all_none():
    r = parse_probe_output("")
    assert r["cpu_usage"] is None
    assert all(r[k] is None for k in (
        "distro", "cpu_model", "cpu_cores", "mem_total_kb", "cpu_temp_c",
        "uptime_seconds", "gpu_name", "gpu_usage", "gpu_temp_c"))


def test_whole_degree_temperatures_are_not_divided():
    r = parse_probe_output(_probe(CPU_TEMP="47"))
    assert r["cpu_temp_c"] == 47


def test_brand_detection():
    assert detect_cpu_brand("Intel(R) Core(TM) i7-8700") is BRANDS["intel"]
    assert detect_cpu_brand("AMD EPYC 7302") is BRANDS["amd"]
    assert detect_cpu_brand(None) is BRANDS["unknown"]
    assert detect_gpu_brand("NVIDIA Quadro P400") is BRANDS["nvidia"]
    assert detect_gpu_brand("Radeon RX 6700 XT") is BRANDS["amd"]
    assert detect_gpu_brand("Intel UHD Graphics 630") is BRANDS["intel"]
    assert detect_gpu_brand("Matrox G200eR2") is BRANDS["unknown"]
    assert detect_gpu_brand("") is BRANDS["unknown"]


# ── health checks ───────────────────────────────────────────────────────────

from lanscanman.core.probe import (  # noqa: E402
    health_summary,
    parse_health,
    unhealthy_containers,
)

# Real output shape, captured from a Ubuntu 24.04 host
REAL_HEALTH = _probe(
    FAILED_UNITS="vboxadd.service",
    UPDATES="dnsmasq-base/noble-updates 2.91-0ubuntu0.24.04.1 amd64 [upgradable from: 2.90]\n"
            "libssl3t64/noble-security 3.0.13-0ubuntu3.6 amd64 [upgradable from: 3.0.13-0ubuntu3.5]\n"
            "tzdata/noble-updates 2025b-0ubuntu0.24.04 all [upgradable from: 2024a]",
    REBOOT="yes",
    DOCKER="web\trunning\tUp 4 hours\nbackup\texited\tExited (1) 2 hours ago\n"
           "oneshot\texited\tExited (0) 3 days ago\ndb\trunning\tUp 2 hours (unhealthy)",
)


def test_parse_health_real_output():
    h = parse_health(split_sections(REAL_HEALTH))
    assert h["failed_units"] == ["vboxadd.service"]
    assert (h["updates"], h["security_updates"]) == (3, 1)
    assert h["reboot_required"] is True and h["docker"] == "ok"
    assert [c["name"] for c in unhealthy_containers(h["containers"])] == ["backup", "db"]
    # a job that finished successfully (Exited (0)) is not a problem


def test_health_summary_real_output():
    text, severity, findings = health_summary(parse_health(split_sections(REAL_HEALTH)))
    assert severity == "bad"
    assert text == "1 failed · 2 containers down · 3 upd (1 sec) · reboot"
    assert "1 failed service(s): vboxadd.service" in findings


def test_healthy_host():
    h = parse_health(split_sections(_probe(FAILED_UNITS="", UPDATES="", REBOOT="no",
                                           DOCKER="DOCKER_ABSENT")))
    assert (h["failed_units"], h["updates"], h["reboot_required"], h["docker"]) == ([], 0, False, "absent")
    assert health_summary(h) == ("OK", "good", [])


def test_updates_only_is_a_warning_unless_security():
    h = parse_health(split_sections(_probe(
        FAILED_UNITS="", REBOOT="no",
        UPDATES="vim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]")))
    assert health_summary(h)[:2] == ("1 upd", "warn")


def test_non_debian_non_systemd_host():
    h = parse_health(split_sections(_probe(FAILED_UNITS="NO_SYSTEMD", UPDATES="NO_APT",
                                           REBOOT="", DOCKER="DOCKER_DENIED")))
    assert (h["failed_units"], h["updates"], h["reboot_required"], h["docker"]) == (None, None, None, "denied")
    assert health_summary(h) == ("—", "unknown", [])


def test_old_probe_output_without_health_sections():
    r = parse_probe_output(NVIDIA_HOST)
    assert r["failed_units"] is None and r["updates"] is None and r["docker"] is None
    assert health_summary(r)[1] == "unknown"


def test_probe_script_is_valid_shell_and_read_only():
    import shutil
    import subprocess

    from lanscanman.core.probe import PROBE_CMD
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n", "-c", PROBE_CMD]).returncode == 0
    for word in ("rm ", "apt install", "apt-get", "upgrade ", "systemctl restart",
                 "docker rm", "docker start", "sudo "):
        assert word not in PROBE_CMD


def test_health_from_json_outputs():
    raw = _probe(
        FAILED_UNITS='[{"unit":"vboxadd.service","load":"loaded","active":"failed","sub":"failed",'
                     '"description":"vboxadd.service"}]',
        UPDATES="", REBOOT="no",
        DOCKER='{"Names":"web","State":"running","Status":"Up 4 hours"}\n'
               '{"Names":"backup","State":"exited","Status":"Exited (1) 2 hours ago"}',
    )
    h = parse_health(split_sections(raw))
    assert h["failed_units"] == ["vboxadd.service"]
    assert [(c["name"], c["state"]) for c in h["containers"]] == [("web", "running"), ("backup", "exited")]
    assert health_summary(h)[0] == "1 failed · 1 container down"


def test_health_json_and_text_agree():
    text = parse_health(split_sections(REAL_HEALTH))
    as_json = parse_health(split_sections(_probe(
        FAILED_UNITS='[{"unit":"vboxadd.service"}]',
        UPDATES=split_sections(REAL_HEALTH)["UPDATES"], REBOOT="yes",
        DOCKER="\n".join(json.dumps({"Names": c["name"], "State": c["state"], "Status": c["status"]})
                         for c in text["containers"]))))
    assert health_summary(as_json) == health_summary(text)


def test_probe_script_uses_json_with_text_fallback():
    from lanscanman.core.probe import PROBE_CMD
    assert "systemctl list-units --failed --output=json" in PROBE_CMD
    assert "systemctl --failed --no-legend --plain" in PROBE_CMD          # older systemd
    assert "docker ps -a --format '{{json .}}'" in PROBE_CMD
