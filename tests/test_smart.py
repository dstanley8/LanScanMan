import pytest

from lanscanman.core.formatting import BAD, GOOD, MUTED, WARN
from lanscanman.core.smart import (
    disk_for_device,
    kelvin_to_c,
    overall_health,
    parse_lsblk_tree,
    parse_one_disk,
    parse_smart_probe,
    parse_udisks_dump,
    smart_text,
)

SATA_SMARTCTL = """\
smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.8.0] (local build)
=== START OF INFORMATION SECTION ===
Model Family:     Samsung based SSDs
Device Model:     Samsung SSD 870 EVO 1TB
Serial Number:    S0EXAMPLE00001A
User Capacity:    1,000,204,886,016 bytes [1.00 TB]

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       3
  9 Power_On_Hours          0x0032   095   095   000    Old_age   Always       -       21034
177 Wear_Leveling_Count     0x0013   097   097   000    Pre-fail  Always       -       45
190 Airflow_Temperature_Cel 0x0032   066   052   000    Old_age   Always       -       34
194 Temperature_Celsius     0x0022   066   052   000    Old_age   Always       -       34 (Min/Max 20/48)
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0
198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       0
241 Total_LBAs_Written      0x0032   099   099   000    Old_age   Always       -       42949672960
"""

NVME_SMARTCTL = """\
=== START OF INFORMATION SECTION ===
Model Number:                       Example NVMe SSD 2TB
Serial Number:                      EXAMPLE00002
=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED
Critical Warning:                   0x00
Temperature:                        41 Celsius
Available Spare:                    100%
Percentage Used:                    2%
Data Units Written:                 25,134,112 [12.8 TB]
Power On Hours:                     4,210
Media and Data Integrity Errors:    0
"""

UDISKS_DUMP = """\
/org/freedesktop/UDisks2/drives/ST4000_ABC:
  org.freedesktop.UDisks2.Drive.Ata:
    SmartFailing:               false
    SmartNumBadSectors:         7
    SmartPowerOnSeconds:        36000000
    SmartTemperature:           308.15
/org/freedesktop/UDisks2/block_devices/sdb:
  org.freedesktop.UDisks2.Block:
    Device:                     /dev/sdb
    Drive:                      '/org/freedesktop/UDisks2/drives/ST4000_ABC'
/org/freedesktop/UDisks2/drives/NVME_XYZ:
  org.freedesktop.UDisks2.NVMe.Controller:
    SmartCriticalWarning:       \x00
    SmartPowerOnHours:          1234
    SmartTemperature:           313
/org/freedesktop/UDisks2/block_devices/nvme1n1:
    Device:                     /dev/nvme1n1
    Drive:                      '/org/freedesktop/UDisks2/drives/NVME_XYZ'
"""


def test_kelvin_to_c():
    assert kelvin_to_c(308.15) == 35
    assert kelvin_to_c(40) == 40        # already Celsius


def test_parse_sata_disk():
    d = parse_one_disk("sda", SATA_SMARTCTL)
    assert d["smart_method"] == "smartctl"
    assert d["smart_ok"] is True
    assert d["model"] == "Samsung SSD 870 EVO 1TB"
    assert d["serial"] == "S0EXAMPLE00001A"
    assert d["capacity_bytes"] == 1_000_204_886_016
    assert d["reallocated"] == 3
    assert d["power_on_hours"] == 21034
    assert d["temperature_c"] == 34          # 190 wins, 194 ignored once set
    assert d["wear_pct_used"] == 3           # 100 - normalised VALUE 097
    assert d["pending"] == 0
    assert d["uncorrectable"] == 0
    assert d["tbw_tb"] == 20.0               # 42949672960 LBAs * 512 B


def test_parse_nvme_disk():
    d = parse_one_disk("nvme0n1", NVME_SMARTCTL)
    assert d["smart_ok"] is True
    assert d["model"] == "Example NVMe SSD 2TB"
    assert d["temperature_c"] == 41
    assert d["power_on_hours"] == 4210
    assert d["wear_pct_used"] == 2
    assert d["available_spare_pct"] == 100
    assert d["tbw_tb"] == 12.8
    assert d["uncorrectable"] == 0


def test_failed_health_and_nvme_critical_warning():
    assert parse_one_disk("sda", "SMART overall-health self-assessment test result: FAILED")["smart_ok"] is False
    assert parse_one_disk("nvme0n1", "Critical Warning: 0x04")["smart_ok"] is False


def test_empty_section_means_smart_unavailable():
    d = parse_one_disk("sda", "")
    assert d["smart_available"] is False
    assert d["smart_method"] is None


def test_parse_udisks_dump_joins_block_devices_to_drives():
    m = parse_udisks_dump(UDISKS_DUMP)
    assert m["/dev/sdb"] == {"smart_ok": True, "uncorrectable": 7,
                             "power_on_hours": 10000, "temperature_c": 35}
    # NVMe: a NUL-byte critical warning counts as healthy
    assert m["/dev/nvme1n1"] == {"smart_ok": True, "power_on_hours": 1234, "temperature_c": 40}


def test_udisks_fallback():
    d = parse_one_disk("sdb", "METHOD:UDISKS", parse_udisks_dump(UDISKS_DUMP))
    assert d["smart_method"] == "udisks"
    assert d["uncorrectable"] == 7
    missing = parse_one_disk("sdz", "METHOD:UDISKS", {})
    assert missing["smart_available"] is False


def test_parse_full_probe():
    raw = f"""###LSBLK###
sda  1000204886016 disk Samsung SSD 870 EVO 1TB
sdb  4000787030016 disk ST4000DM004-2CV1
nvme0n1 2000398934016 disk Example NVMe SSD
###DF###
/dev/sda1   500000000000 200000000000 300000000000  40% /
/dev/sda2   500000000000 100000000000 400000000000  20% /home
/dev/nvme0n1p2 1000000000000 1000 999999999000 1% /data
###UDISKS_DUMP###
{UDISKS_DUMP}
###SMART_START:sda###
{SATA_SMARTCTL}
###SMART_END:sda###
###SMART_START:sdb###
METHOD:UDISKS
###SMART_END:sdb###
###SMART_START:nvme0n1###
{NVME_SMARTCTL}
###SMART_END:nvme0n1###
"""
    disks = {d["dev"]: d for d in parse_smart_probe(raw)}
    assert list(disks) == ["sda", "sdb", "nvme0n1"]
    assert disks["sda"]["fs_used_bytes"] == 300_000_000_000   # partitions summed
    assert disks["sda"]["fs_total_bytes"] == 1_000_000_000_000
    assert disks["nvme0n1"]["fs_used_bytes"] == 1000
    assert disks["sdb"]["fs_used_bytes"] is None
    assert disks["sdb"]["model"] == "ST4000DM004-2CV1"         # from lsblk
    assert disks["sdb"]["capacity_bytes"] == 4000787030016
    assert disks["sdb"]["smart_method"] == "udisks"


def test_overall_health():
    ok = {"smart_available": True, "smart_ok": True}
    assert overall_health([]) == ("No disks", MUTED)
    assert overall_health([{"smart_available": False}])[1] == MUTED
    assert overall_health([ok, ok]) == ("2 disk(s) — all OK", GOOD)
    assert overall_health([ok, {"smart_available": True, "smart_ok": None}])[1] == WARN
    assert overall_health([ok, {"smart_available": True, "smart_ok": False}])[1] == BAD


def test_smart_text():
    assert smart_text(True, False) == "N/A"
    assert smart_text(True, True) == "PASSED"
    assert smart_text(False, True) == "FAILED!"
    assert smart_text(None, True) == "?"


LSBLK_TREE = """\
/dev/sda
/dev/sda1 /dev/sda
/dev/sda2 /dev/sda
/dev/mmcblk0
/dev/mmcblk0p1 /dev/mmcblk0
/dev/nvme0n1
/dev/nvme0n1p3 /dev/nvme0n1
/dev/mapper/cryptroot /dev/nvme0n1p3
/dev/mapper/vg-root /dev/mapper/cryptroot
"""


def test_disk_for_device_follows_lvm_and_luks_stacks():
    parents = parse_lsblk_tree(LSBLK_TREE)
    assert disk_for_device("/dev/mapper/vg-root", parents) == "nvme0n1"
    assert disk_for_device("/dev/sda1", parents) == "sda"
    assert disk_for_device("/dev/mmcblk0p1", parents) == "mmcblk0"


def test_disk_for_device_without_tree():
    # Fallback name matching (e.g. lsblk too old for PKNAME)
    assert disk_for_device("/dev/sdb3", {}) == "sdb"
    assert disk_for_device("/dev/nvme1n1p1", {}) == "nvme1n1"
    assert disk_for_device("/dev/mmcblk1p2", {}) == "mmcblk1"
    assert disk_for_device("/dev/mapper/vg-root", {}) is None


def test_disk_for_device_survives_a_cycle():
    assert disk_for_device("/dev/a", {"/dev/a": "/dev/b", "/dev/b": "/dev/a"}) in ("a", "b")


def test_full_probe_attributes_lvm_usage_to_its_disk():
    raw = f"""###LSBLK###
nvme0n1 512110190592 disk Samsung SSD 980
mmcblk0 31914983424 disk
###LSBLK_TREE###
{LSBLK_TREE}
###DF###
/dev/mapper/vg-root 400000000000 150000000000 250000000000 38% /
/dev/nvme0n1p1 1000000000 50000000 950000000 5% /boot/efi
/dev/mmcblk0p1 31000000000 1000 30999999000 1% /media/sd
"""
    disks = {d["dev"]: d for d in parse_smart_probe(raw)}
    assert disks["nvme0n1"]["fs_used_bytes"] == 150_050_000_000
    assert disks["mmcblk0"]["fs_used_bytes"] == 1000


# ── smartctl -j (smartmontools 7.0+) — real captured outputs ────────────────

import json  # noqa: E402
from pathlib import Path  # noqa: E402

from lanscanman.core.smart import _three_significant, parse_lsblk_json  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "smartctl"


def _fixture(name):
    return (FIXTURES / name).read_text()


def test_json_sata_hdd():
    d = parse_one_disk("sda", _fixture("WDC_WD20EFRX-68EUZN0_17.json"))
    assert d["smart_format"] == "json" and d["smart_method"] == "smartctl"
    assert d["model"] == "WDC WD20EFRX-68EUZN0" and d["capacity_bytes"] == 2000398934016
    assert d["smart_ok"] is True and d["temperature_c"] == 34
    assert d["power_on_hours"] == 47657
    assert (d["reallocated"], d["pending"], d["uncorrectable"]) == (0, 0, 0)
    assert d["wear_pct_used"] is None and d["tbw_tb"] is None       # an HDD reports neither


def test_json_sata_ssd():
    d = parse_one_disk("sdb", _fixture("SAMSUNG_MZ7WD240HAFV-00003_21.json"))
    assert d["model"] == "SAMSUNG MZ7WD240HAFV-00003"
    assert d["temperature_c"] == 27 and d["power_on_hours"] == 84619
    assert d["wear_pct_used"] == 9                       # 100 - normalised value 91
    assert d["tbw_tb"] == round(216456537880 * 512 / 1024 ** 4, 2)   # same formula as text


def test_json_nvme():
    d = parse_one_disk("nvme0n1", _fixture("SAMSUNG_MZVL21T0HCLR-00B00_23.json"))
    assert d["model"] == "SAMSUNG MZVL21T0HCLR-00B00" and d["smart_ok"] is True
    assert d["temperature_c"] == 29 and d["power_on_hours"] == 10423
    assert d["wear_pct_used"] == 16 and d["available_spare_pct"] == 100
    assert d["uncorrectable"] == 0
    assert d["tbw_tb"] == 58.2                           # 113662783 units -> "58.2 TB", like smartctl shows


def test_json_nvme_critical_warning_fails_health():
    data = json.loads(_fixture("SAMSUNG_MZVL21T0HCLR-00B00_23.json"))
    data["nvme_smart_health_information_log"]["critical_warning"] = 4
    assert parse_one_disk("nvme0n1", json.dumps(data))["smart_ok"] is False


def test_json_failed_health():
    data = json.loads(_fixture("WDC_WD20EFRX-68EUZN0_17.json"))
    data["smart_status"]["passed"] = False
    assert parse_one_disk("sda", json.dumps(data))["smart_ok"] is False


def test_json_packed_raw_values_use_the_displayed_number():
    data = json.loads(_fixture("WDC_WD20EFRX-68EUZN0_17.json"))
    del data["temperature"], data["power_on_time"]
    for a in data["ata_smart_attributes"]["table"]:
        if a["id"] == 194:
            a["raw"] = {"value": 206158430242, "string": "34 (Min/Max 20/48)"}
        if a["id"] == 9:
            a["raw"] = {"value": 5000000000000, "string": "47657h+12m+30.123s"}
    d = parse_one_disk("sda", json.dumps(data))
    assert d["temperature_c"] == 34 and d["power_on_hours"] == 47657


def test_json_and_text_agree_for_the_same_drive():
    """Switching a host to smartctl -j must not register as a change in the
    SMART history (or fire an alert)."""
    text = parse_one_disk("sda", SATA_SMARTCTL)
    data = {
        "model_name": "Samsung SSD 870 EVO 1TB", "serial_number": "S0EXAMPLE00001A",
        "user_capacity": {"bytes": 1000204886016}, "smart_status": {"passed": True},
        "power_on_time": {"hours": 21034},
        "ata_smart_attributes": {"table": [
            {"id": 5, "value": 100, "raw": {"value": 3, "string": "3"}},
            {"id": 9, "value": 95, "raw": {"value": 21034, "string": "21034"}},
            {"id": 177, "value": 97, "raw": {"value": 45, "string": "45"}},
            {"id": 190, "value": 66, "raw": {"value": 34, "string": "34"}},
            {"id": 197, "value": 100, "raw": {"value": 0, "string": "0"}},
            {"id": 198, "value": 100, "raw": {"value": 0, "string": "0"}},
            {"id": 241, "value": 99, "raw": {"value": 42949672960, "string": "42949672960"}},
        ]},
    }
    js = parse_one_disk("sda", json.dumps(data))
    for key in ("model", "serial", "capacity_bytes", "smart_ok", "temperature_c", "power_on_hours",
                "reallocated", "pending", "uncorrectable", "wear_pct_used", "tbw_tb"):
        assert js[key] == text[key], key


def test_malformed_json_falls_back_to_text_parsing():
    d = parse_one_disk("sda", "{not json\nSMART overall-health self-assessment test result: PASSED")
    assert d["smart_ok"] is True


@pytest.mark.parametrize("x, expected", [(58.1953, 58.2), (12.847, 12.8), (1.2345, 1.23),
                                         (123.4, 123.0), (0.04567, 0.0457), (0, 0.0)])
def test_three_significant(x, expected):
    assert _three_significant(x) == expected


def test_lsblk_json():
    text = json.dumps({"blockdevices": [
        {"name": "loop0", "size": 77574144, "type": "loop", "model": None},
        {"name": "sda", "size": 1000204886016, "type": "disk", "model": "Samsung SSD 870 EVO 1TB"},
        {"name": "sr0", "size": 1073741312, "type": "rom", "model": "DVD"},
        {"name": "nvme0n1", "size": "512110190592", "type": "disk", "model": None},   # old lsblk: strings
    ]})
    assert parse_lsblk_json(text) == {
        "sda": {"size_bytes": 1000204886016, "model": "Samsung SSD 870 EVO 1TB"},
        "nvme0n1": {"size_bytes": 512110190592, "model": None},
    }
    assert parse_lsblk_json("") == {} and parse_lsblk_json("garbage") == {}


def test_full_probe_with_json_sections():
    raw = (
        "###LSBLK_JSON###\n"
        + json.dumps({"blockdevices": [{"name": "nvme0n1", "size": 1024209543168,
                                        "type": "disk", "model": "SAMSUNG MZVL21T0HCLR-00B00"}]})
        + "\n###LSBLK###\nnvme0n1 1024209543168 disk SAMSUNG\n"
        + "###DF###\n/dev/nvme0n1p2 1000000000000 250000000000 750000000000 25% /\n"
        + "###SMART_START:nvme0n1###\n" + _fixture("SAMSUNG_MZVL21T0HCLR-00B00_23.json")
        + "\n###SMART_END:nvme0n1###\n")
    (disk,) = parse_smart_probe(raw)
    assert disk["dev"] == "nvme0n1" and disk["smart_format"] == "json"
    assert disk["fs_used_bytes"] == 250000000000 and disk["wear_pct_used"] == 16


def test_probe_script_prefers_json_with_fallbacks():
    from lanscanman.core.smart import SMART_PROBE_CMD
    assert "smartctl -j --version" in SMART_PROBE_CMD and "smartctl $SMJ -iAH" in SMART_PROBE_CMD
    assert "lsblk -J" in SMART_PROBE_CMD and "###LSBLK###" in SMART_PROBE_CMD   # text kept for old hosts
    assert "METHOD:UDISKS" in SMART_PROBE_CMD
