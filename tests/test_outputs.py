"""行为验收：边界策略台账的下发编译契约。"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

APP = Path(os.environ.get("TASK_APP", "/app/compile_firewall_policy.py"))
DATA = Path(os.environ.get("TASK_DATA_DIR", "/data"))
CALL_TIMEOUT_SEC = 60
TRAILER = "default deny"


def _objects(address_objects, service_objects):
    return {"address_objects": address_objects, "service_objects": service_objects}


def _entry(seq, src_zone, dst_zone, address, service, action="permit", translate_to=None):
    entry = {
        "seq": seq,
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "address": address,
        "service": service,
        "action": action,
    }
    if translate_to is not None:
        entry["translate_to"] = translate_to
    return entry


def _ledger_text(ledger):
    return json.dumps(ledger, ensure_ascii=False, indent=2) + "\n"


def _objects_text(objects):
    return json.dumps(objects, ensure_ascii=False, indent=2) + "\n"


def _run_compiler(work, ledger_text, objects_text, rules_path=None, report_path=None, journal_path=None):
    work.mkdir(parents=True, exist_ok=True)
    ledger_path = work / "ledger.json"
    objects_path = work / "objects.json"
    ledger_path.write_text(ledger_text, encoding="utf-8")
    objects_path.write_text(objects_text, encoding="utf-8")
    rules = rules_path if rules_path is not None else work / "rules.txt"
    report = report_path if report_path is not None else work / "report.json"
    journal = journal_path if journal_path is not None else work / "journal.jsonl"
    rules_before = rules.read_bytes() if rules.exists() else None
    report_before = report.read_bytes() if report.exists() else None
    journal_before = journal.read_bytes() if journal.exists() else None
    finished = subprocess.run(
        [
            sys.executable,
            str(APP),
            str(ledger_path),
            str(objects_path),
            str(rules),
            str(report),
            str(journal),
        ],
        capture_output=True,
        text=True,
        timeout=CALL_TIMEOUT_SEC,
    )
    finished.work = work
    finished.rules_path = rules
    finished.report_path = report
    finished.journal_path = journal
    finished.rules_before = rules_before
    finished.report_before = report_before
    finished.journal_before = journal_before
    return finished, rules, report


def _work_dir(tmp_path, tag):
    return tmp_path / ("case-" + hashlib.sha256(tag.encode("utf-8")).hexdigest()[:12])


def _compile(tmp_path, tag, ledger, objects):
    return _run_compiler(_work_dir(tmp_path, tag), _ledger_text(ledger), _objects_text(objects))


def _compile_text(tmp_path, tag, ledger_text, objects):
    return _run_compiler(_work_dir(tmp_path, tag), ledger_text, _objects_text(objects))


def _rejection_kept_outputs(finished):
    if finished.returncode == 0:
        return False
    for path, before in (
        (finished.rules_path, finished.rules_before),
        (finished.report_path, finished.report_before),
        (finished.journal_path, finished.journal_before),
    ):
        after = path.read_bytes() if path.exists() else None
        if after != before:
            return False
    allowed = {"ledger.json", "objects.json", "rules.txt", "report.json", "journal.jsonl"}
    return not [path.name for path in finished.work.iterdir() if path.name not in allowed]


def _program_lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _rows(path):
    return [line.split() for line in _program_lines(path) if line != TRAILER]


def _report(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _seqs(path):
    return [row[0] for row in _rows(path)]


def _shadowed_seqs(path, key):
    return [item["seq"] for item in _report(path)[key]]


def _journal_records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _dispatch_paths(work):
    return (
        work / "edge-a1.txt",
        work / "edge-a1-report.json",
        work / "journal.jsonl",
    )


SIMPLE_OBJECTS = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["80"]}})
SIMPLE_LEDGER = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one")]
SIMPLE_ROW = ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.0-198.51.100.255"]

SHIPPED_RULE_ROWS = [
    "1 permit zone-hq-core zone-dmz-edge tcp 80 198.51.100.0-198.51.100.255",
    "1 permit zone-hq-core zone-dmz-edge tcp 443 198.51.100.0-198.51.100.255",
    "2 permit zone-hq-core zone-dmz-edge tcp 53 198.51.100.0-198.51.100.255",
    "2 permit zone-hq-core zone-dmz-edge udp 53 198.51.100.0-198.51.100.255",
    "3 permit zone-hq-core zone-dmz-edge tcp 8080-8100 198.51.100.0-198.51.100.255",
    "5 deny zone-hq-core zone-dmz-edge tcp 8020-8059 203.0.113.64-203.0.113.127",
    "6 permit zone-hq-core zone-dmz-edge tcp 8000-8019 203.0.113.64-203.0.113.127",
    "6 permit zone-hq-core zone-dmz-edge tcp 8060-8100 203.0.113.64-203.0.113.127",
    "7 permit zone-hq-core zone-dmz-edge udp 123 192.0.2.0-192.0.2.191",
    "8 deny zone-hq-core zone-dmz-edge tcp 8000-8049 198.51.100.0-198.51.100.63",
    "9 permit zone-hq-core zone-dmz-edge tcp 8000-8049 198.51.100.64-198.51.100.255",
    "9 permit zone-hq-core zone-dmz-edge tcp 8050-8079 198.51.100.0-198.51.100.255",
    "10 permit zone-dmz-edge zone-dc-app tcp 8000-8100 198.18.0.0-198.18.0.255",
    "10 permit zone-dmz-edge zone-dc-app tcp 8000-8100 198.18.2.0-198.18.2.255",
    "13 permit zone-dmz-edge zone-dc-app tcp 8443 198.18.4.0-198.18.4.255",
    "13 permit zone-dmz-edge zone-dc-app tcp 9100-9102 198.18.4.0-198.18.4.255",
    "13 permit zone-dmz-edge zone-dc-app udp 4789 198.18.4.0-198.18.4.255",
    "14 permit zone-ot-legacy zone-dc-app tcp 3306 203.0.113.128-203.0.113.255",
    "16 translate zone-vpn-partner zone-dc-app tcp 22 198.51.100.192-198.51.100.207 -> 198.18.30.0-198.18.30.255",
    "18 permit zone-vpn-partner zone-dc-app tcp 3306 198.51.100.192-198.51.100.207",
    "19 permit zone-dmz-edge zone-hq-core tcp 80 198.51.100.0-198.51.100.255",
    "19 permit zone-dmz-edge zone-hq-core tcp 443 198.51.100.0-198.51.100.255",
    "20 permit zone-hq-core zone-payroll-bldg3 tcp 139 203.0.113.0-203.0.113.63",
    "20 permit zone-hq-core zone-payroll-bldg3 tcp 139 203.0.113.70-203.0.113.80",
    "20 permit zone-hq-core zone-payroll-bldg3 tcp 445 203.0.113.0-203.0.113.63",
    "20 permit zone-hq-core zone-payroll-bldg3 tcp 445 203.0.113.70-203.0.113.80",
    "21 deny zone-hq-core zone-payroll-bldg3 tcp 139 203.0.113.64-203.0.113.69",
    "21 deny zone-hq-core zone-payroll-bldg3 tcp 139 203.0.113.81-203.0.113.95",
    "21 deny zone-hq-core zone-payroll-bldg3 tcp 445 203.0.113.64-203.0.113.69",
    "21 deny zone-hq-core zone-payroll-bldg3 tcp 445 203.0.113.81-203.0.113.95",
    "22 permit zone-hq-core zone-payroll-bldg3 tcp 515 203.0.113.0-203.0.113.31",
    "22 permit zone-hq-core zone-payroll-bldg3 tcp 515 203.0.113.64-203.0.113.95",
    "22 permit zone-hq-core zone-payroll-bldg3 tcp 631-640 203.0.113.0-203.0.113.31",
    "22 permit zone-hq-core zone-payroll-bldg3 tcp 631-640 203.0.113.64-203.0.113.95",
    "23 permit zone-wifi-guest zone-dmz-edge tcp 80 198.18.8.0-198.18.10.127",
    "23 permit zone-wifi-guest zone-dmz-edge tcp 443 198.18.8.0-198.18.10.127",
    "24 deny zone-hq-core zone-wifi-guest tcp 80 198.18.8.0-198.18.10.127",
    "24 deny zone-hq-core zone-wifi-guest tcp 443 198.18.8.0-198.18.10.127",
    "25 permit zone-mgmt-plane zone-hq-core tcp 22 192.0.2.254",
    "26 translate zone-hq-core zone-payroll-bldg3 udp 123 203.0.113.0-203.0.113.31 -> 203.0.113.232-203.0.113.239",
    "26 translate zone-hq-core zone-payroll-bldg3 udp 123 203.0.113.64-203.0.113.95 -> 203.0.113.232-203.0.113.239",
    "27 deny zone-dmz-edge zone-dc-app tcp 515 192.0.2.192-192.0.2.255",
    "27 deny zone-dmz-edge zone-dc-app tcp 10050-10090 192.0.2.192-192.0.2.255",
    "27 deny zone-dmz-edge zone-dc-app udp 4789 192.0.2.192-192.0.2.255",
    "28 deny zone-dmz-edge zone-dc-app tcp 3306 192.0.2.192-192.0.2.255",
    "29 permit zone-dmz-edge zone-dc-app tcp 3306 192.0.2.128-192.0.2.191",
]
SHIPPED_REPORT = {
    "entries": 29,
    "rules": 46,
    "dropped": [{"seq": 4, "shadowed_by": [1]}, {"seq": 11, "shadowed_by": [10]}, {"seq": 12, "shadowed_by": [10, 11]}, {"seq": 15, "shadowed_by": [14]}, {"seq": 17, "shadowed_by": [16]}],
    "split": [{"seq": 6, "lines": 2, "shadowed_by": [5]}, {"seq": 9, "lines": 2, "shadowed_by": [3, 8]}, {"seq": 21, "lines": 4, "shadowed_by": [20]}, {"seq": 29, "lines": 1, "shadowed_by": [28]}],
}



def test_rejects_duplicate_key_inside_ledger_entry(tmp_path):
    """题面「同一层 JSON 里出现两次同样的键名」：条目里重复的键名整批拒收。"""
    text = (
        '[{"seq": 1, "src_zone": "zone-hq-core", "dst_zone": "zone-dmz-edge",'
        ' "address": "addr-one", "service": "svc-one", "action": "permit", "action": "deny"}]\n'
    )
    finished, rules_path, _ = _compile_text(tmp_path, "case-01", text, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()


def test_rejects_unknown_field_inside_ledger_entry(tmp_path):
    """题面「条目上多出字典里没有的字段名」：条目多带一个字段名就整批拒收。"""
    entry = _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one")
    entry["change_ticket"] = "CHG-20261016"
    finished, _, _ = _compile(tmp_path, "case-02", [entry], SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)


def test_rejects_entry_missing_service_field(tmp_path):
    """题面「元素是对象，允许出现的键名就这几个」：条目少一个键名就整批拒收。"""
    entry = _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one")
    entry.pop("service")
    finished, _, _ = _compile(tmp_path, "case-03", [entry], SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)

def test_rejects_bad_sequence_numbering(tmp_path):
    """题面「序号重复、跳号，数组顺序跟序号对不上，或者序号不是整数」：三种序号问题都整批拒收。"""
    repeated = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
        _entry(3, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
    ]
    repeated_run, _, _ = _compile(tmp_path, "case-04", repeated, SIMPLE_OBJECTS)
    gapped = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
        _entry(4, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
    ]
    gapped_run, _, _ = _compile(tmp_path, "case-05", gapped, SIMPLE_OBJECTS)
    shuffled = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(3, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
    ]
    shuffled_run, _, _ = _compile(tmp_path, "case-06", shuffled, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(repeated_run)
    assert _rejection_kept_outputs(gapped_run)
    assert _rejection_kept_outputs(shuffled_run)


def test_rejects_translate_target_mismatch(tmp_path):
    """题面「动作名不认识，或者转换目标跟动作对不上」：转换目标与动作对不上的两种写法都拒收。"""
    missing = [_entry(1, "zone-vpn-partner", "zone-dc-app", "addr-one", "svc-one", "translate")]
    missing_run, _, _ = _compile(tmp_path, "case-07", missing, SIMPLE_OBJECTS)
    extra = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "permit", "198.18.30.5")
    ]
    extra_run, _, _ = _compile(tmp_path, "case-08", extra, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(missing_run)
    assert _rejection_kept_outputs(extra_run)


def test_rejects_bad_port_items(tmp_path):
    """题面「端口写成负数、超过 65535，区间前后写反」：三种端口写法都整批拒收。"""
    too_high = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["80", "65536"]}})
    high_run, _, _ = _compile(tmp_path, "case-09", SIMPLE_LEDGER, too_high)
    reversed_range = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["8090-8080"]}})
    reversed_run, _, _ = _compile(tmp_path, "case-10", SIMPLE_LEDGER, reversed_range)
    negative = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["-1"]}})
    negative_run, _, _ = _compile(tmp_path, "case-11", SIMPLE_LEDGER, negative)
    assert _rejection_kept_outputs(high_run)
    assert _rejection_kept_outputs(reversed_run)
    assert _rejection_kept_outputs(negative_run)


def test_rejects_bad_objects_document(tmp_path):
    """题面「对象字典里的地址项既不是 CIDR 又不是合法区间，协议名不是 tcp 也不是 udp」。"""
    bad_cidr = _objects({"addr-one": ["198.51.100.0/33"]}, {"svc-one": {"tcp": ["80"]}})
    cidr_run, _, _ = _compile(tmp_path, "case-12", SIMPLE_LEDGER, bad_cidr)
    bad_protocol = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"sctp": ["3868"]}})
    protocol_run, _, _ = _compile(tmp_path, "case-13", SIMPLE_LEDGER, bad_protocol)
    assert _rejection_kept_outputs(cidr_run)
    assert _rejection_kept_outputs(protocol_run)


def test_rejects_translation_target_inside_translation_match(tmp_path):
    """题面「地址转换条目改写出来的地址落进了某条地址转换条目的匹配地址里」：改写链整批拒收。"""
    objects = _objects(
        {"addr-inner": ["198.18.30.0/24"], "addr-outer": ["198.51.100.192/28"]},
        {"svc-ssh": {"tcp": ["22"]}},
    )
    self_loop = [
        _entry(1, "zone-vpn-partner", "zone-dc-app", "addr-inner", "svc-ssh", "translate", "198.18.30.64/26")
    ]
    loop_run, _, _ = _compile(tmp_path, "case-14", self_loop, objects)
    chained = [
        _entry(1, "zone-vpn-partner", "zone-dc-app", "addr-outer", "svc-ssh", "translate", "198.18.30.0/24"),
        _entry(2, "zone-vpn-partner", "zone-dc-app", "addr-inner", "svc-ssh", "translate", "203.0.113.232/29"),
    ]
    chain_run, _, _ = _compile(tmp_path, "case-15", chained, objects)
    assert _rejection_kept_outputs(loop_run)
    assert _rejection_kept_outputs(chain_run)



def test_rejects_unknown_action_name(tmp_path):
    """题面「动作名不认识」：动作名写在三个合法值之外的条目整批拒收。"""
    ledger = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "reject")]
    finished, _, _ = _compile(tmp_path, "case-16", ledger, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)


def test_rejects_zone_name_with_whitespace(tmp_path):
    """题面「源区或者目的区缺失、写空、带空白字符」：区名带空格的台账整批拒收。"""
    ledger = [_entry(1, "zone hq core", "zone-dmz-edge", "addr-one", "svc-one")]
    finished, _, _ = _compile(tmp_path, "case-17", ledger, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)


def test_rejects_undefined_object_reference(tmp_path):
    """题面「条目引用的地址对象或者服务对象在对象字典里找不到」：未定义引用整批拒收。"""
    ledger = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-nowhere", "svc-one")]
    finished, rules_path, report_path = _compile(tmp_path, "case-18", ledger, SIMPLE_OBJECTS)
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert not report_path.exists()


def test_accepts_port_and_address_boundary_values(tmp_path):
    """题面「0 到 65535 的整数」：端口两端与单地址对象都是合法输入。"""
    objects = _objects({"addr-one": ["192.0.2.254"]}, {"svc-one": {"tcp": ["0", "65535"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-19", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "0", "192.0.2.254"],
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "65535", "192.0.2.254"],
    ]


def test_adjacent_address_items_merge_into_one_span(tmp_path):
    """题面「相邻或者叠在一起的网段本来就是同一片地址」：相接的两个地址项并成一条。"""
    objects = _objects({"addr-one": ["198.51.100.0/25", "198.51.100.128-198.51.100.255"]}, {"svc-one": {"tcp": ["80"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-20", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.0-198.51.100.255"],
    ]


def test_adjacent_port_items_merge_into_one_range(tmp_path):
    """题面「同一协议下相邻或者叠在一起的端口段也是同一段端口」：相接的两个端口段并成一条。"""
    objects = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["8080-8090", "8091-8100"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-21", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "8080-8100", "198.51.100.0-198.51.100.255"],
    ]


def test_port_items_stay_separate_across_protocols(tmp_path):
    """题面「跨协议、跨对象、跨区对的那是另一片，不能并到一起」：两个协议各写一行。"""
    objects = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["80", "81-90"], "udp": ["80", "81-90"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-22", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80-90", "198.51.100.0-198.51.100.255"],
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "udp", "80-90", "198.51.100.0-198.51.100.255"],
    ]


def test_overlapping_address_items_collapse_to_one_span(tmp_path):
    """题面「相邻或者叠在一起的网段本来就是同一片地址」：完全叠住的两个地址项合成一条。"""
    objects = _objects({"addr-one": ["198.51.100.0/25", "198.51.100.0-198.51.100.127"]}, {"svc-one": {"tcp": ["80"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-23", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.0-198.51.100.127"],
    ]


def test_nested_range_merges_into_widest_span(tmp_path):
    """题面「相邻或者叠在一起的网段本来就是同一片地址」：被大区间包住的小网段不再单写一行。"""
    objects = _objects({"addr-one": ["198.51.100.0-198.51.100.255", "198.51.100.64/26"]}, {"svc-one": {"tcp": ["80"]}})
    finished, rules_path, _ = _compile(tmp_path, "case-24", SIMPLE_LEDGER, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.0-198.51.100.255"],
    ]


def test_fully_shadowed_entry_is_not_emitted(tmp_path):
    """题面「被比它更早、跟它交得上的那些条目整片盖住，它就白写，不下发」：整片遮住的不下发。"""
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "deny"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-25", ledger, SIMPLE_OBJECTS)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [SIMPLE_ROW]
    assert _shadowed_seqs(report_path, "dropped") == [2]


def test_partially_shadowed_entry_keeps_remaining_addresses(tmp_path):
    """题面「只被盖住一部分的，下发的是它还剩的那部分」：剩下的地址接着往下写。"""
    objects = _objects(
        {"addr-low": ["198.51.100.0/25"], "addr-all": ["198.51.100.0-198.51.100.255"]},
        {"svc-one": {"tcp": ["80"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-low", "svc-one"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-all", "svc-one", "deny"),
    ]
    finished, rules_path, _ = _compile(tmp_path, "case-26", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.0-198.51.100.127"],
        ["2", "deny", "zone-hq-core", "zone-dmz-edge", "tcp", "80", "198.51.100.128-198.51.100.255"],
    ]


def test_partial_shadowing_splits_port_axis_where_addresses_change(tmp_path):
    """题面「端口轴上剩下的地址变了，那里就断开写下一段」：端口轴上按剩余地址断开。"""
    objects = _objects(
        {"addr-front": ["198.51.100.0/26"], "addr-wide": ["198.51.100.0/25", "198.51.100.128-198.51.100.255"]},
        {"svc-short": {"tcp": ["8000-8049"]}, "svc-wide": {"tcp": ["8000-8100"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-front", "svc-short", "deny"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-wide", "svc-wide", "permit"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-27", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "deny", "zone-hq-core", "zone-dmz-edge", "tcp", "8000-8049", "198.51.100.0-198.51.100.63"],
        ["2", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "8000-8049", "198.51.100.64-198.51.100.255"],
        ["2", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "8050-8100", "198.51.100.0-198.51.100.255"],
    ]
    assert _report(report_path)["split"] == [{"seq": 2, "lines": 2, "shadowed_by": [1]}]


def test_reversed_zone_pair_is_not_shadowed(tmp_path):
    """题面「源区到目的区被盖住，不代表反方向也盖住」：反方向那条照常下发。"""
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(2, "zone-dmz-edge", "zone-hq-core", "addr-one", "svc-one"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-28", ledger, SIMPLE_OBJECTS)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        SIMPLE_ROW,
        ["2", "permit", "zone-dmz-edge", "zone-hq-core", "tcp", "80", "198.51.100.0-198.51.100.255"],
    ]
    assert _report(report_path)["dropped"] == []


def test_translate_entry_shadows_later_policy_entry(tmp_path):
    """题面「每条规则按序号排下来，转换条目自然落在它改写过的那些匹配条目前面」。"""
    objects = _objects(
        {"addr-wide": ["198.51.100.192/28"], "addr-narrow": ["198.51.100.192/29"]},
        {"svc-ssh": {"tcp": ["22"]}},
    )
    ledger = [
        _entry(1, "zone-vpn-partner", "zone-dc-app", "addr-wide", "svc-ssh", "translate", "198.18.30.0/24"),
        _entry(2, "zone-vpn-partner", "zone-dc-app", "addr-narrow", "svc-ssh", "deny"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-29", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "translate", "zone-vpn-partner", "zone-dc-app", "tcp", "22", "198.51.100.192-198.51.100.207", "->", "198.18.30.0-198.18.30.255"],
    ]
    assert _shadowed_seqs(report_path, "dropped") == [2]


def test_rule_rows_follow_ledger_sequence_order(tmp_path):
    """题面「整个文件按条目序号从小到大排」：行序按序号升序，不按文本排序。"""
    address_objects = {}
    ledger = []
    for number in range(1, 13):
        name = "addr-%s" % (chr(96 + number),)
        address_objects[name] = ["198.18.%d.0/24" % (number,)]
        ledger.append(_entry(number, "zone-hq-core", "zone-dmz-edge", name, "svc-one"))
    finished, rules_path, _ = _compile(tmp_path, "case-30", ledger, _objects(address_objects, {"svc-one": {"tcp": ["80"]}}))
    assert finished.returncode == 0, finished.stderr
    assert _seqs(rules_path) == ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]


def test_rows_inside_one_entry_sort_by_port_then_address(tmp_path):
    """题面「先按协议名排，再按端口段起点排，再按地址段起点排」：同一条内的行序。"""
    objects = _objects(
        {"addr-one": ["198.51.100.0/24"]},
        {"svc-mixed": {"tcp": ["515", "10050-10090"], "udp": ["4789"]}},
    )
    ledger = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-mixed")]
    finished, rules_path, _ = _compile(tmp_path, "case-31", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "515", "198.51.100.0-198.51.100.255"],
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "10050-10090", "198.51.100.0-198.51.100.255"],
        ["1", "permit", "zone-hq-core", "zone-dmz-edge", "udp", "4789", "198.51.100.0-198.51.100.255"],
    ]


def test_blocked_middle_port_slice_splits_remaining_ports(tmp_path):
    """题面「端口轴上剩下的地址变了，那里就断开写下一段」：中间被挡住的端口段切开。"""
    objects = _objects(
        {"addr-one": ["198.51.100.0/24"]},
        {"svc-mid": {"tcp": ["8020-8059"]}, "svc-wide": {"tcp": ["8000-8100"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-mid", "deny"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-wide", "permit"),
    ]
    finished, rules_path, _ = _compile(tmp_path, "case-32", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "deny", "zone-hq-core", "zone-dmz-edge", "tcp", "8020-8059", "198.51.100.0-198.51.100.255"],
        ["2", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "8000-8019", "198.51.100.0-198.51.100.255"],
        ["2", "permit", "zone-hq-core", "zone-dmz-edge", "tcp", "8060-8100", "198.51.100.0-198.51.100.255"],
    ]


def test_rule_row_carries_fields_in_declared_order(tmp_path):
    """题面「一行里的字段从左到右按下表排，中间隔一个空格」：普通放行行的字段顺序。"""
    finished, rules_path, _ = _compile(tmp_path, "case-33", SIMPLE_LEDGER, SIMPLE_OBJECTS)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [SIMPLE_ROW]


def test_program_ends_with_default_action_and_lf(tmp_path):
    """题面「设备上没被任何一条命中的流量按拒处理」：兜底那一行排在最后。"""
    finished, rules_path, _ = _compile(tmp_path, "case-34", SIMPLE_LEDGER, SIMPLE_OBJECTS)
    assert finished.returncode == 0, finished.stderr
    text = rules_path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    assert "\r" not in text
    assert _program_lines(rules_path)[-1] == TRAILER


def test_translate_row_carries_arrow_and_target(tmp_path):
    """题面「条目有这一位，先写」：转换行先写箭头再写改写后的地址段。"""
    objects = _objects({"addr-one": ["198.51.100.0/24"]}, {"svc-one": {"tcp": ["443"]}})
    ledger = [_entry(1, "zone-vpn-partner", "zone-dc-app", "addr-one", "svc-one", "translate", "198.18.30.5")]
    finished, rules_path, _ = _compile(tmp_path, "case-35", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules_path) == [
        ["1", "translate", "zone-vpn-partner", "zone-dc-app", "tcp", "443", "198.51.100.0-198.51.100.255", "->", "198.18.30.5"],
    ]


def test_report_is_one_compact_line_with_ordered_keys(tmp_path):
    """题面「报表落成一行 JSON，键与值之间、值与值之间都不留空格」：字段顺序与紧凑写法。"""
    objects = _objects(
        {"addr-one": ["198.51.100.0/24"], "addr-two": ["198.18.40.0/24"]},
        {"svc-one": {"tcp": ["80"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one"),
        _entry(2, "zone-hq-core", "zone-wifi-guest", "addr-two", "svc-one"),
    ]
    finished, _, report_path = _compile(tmp_path, "case-36", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    text = report_path.read_text(encoding="utf-8")
    assert text.count("\n") == 1
    assert ", " not in text
    assert list(_report(report_path)) == ["entries", "rules", "dropped", "split"]
    assert _report(report_path) == {"entries": 2, "rules": 2, "dropped": [], "split": []}


def test_report_lists_dropped_entries_with_shadowing_references(tmp_path):
    """题面「是被整片盖住、没有下发的条目，按序号从小到大」：报表里的剔除清单。"""
    objects = _objects(
        {"addr-low": ["198.51.100.0/25"], "addr-all": ["198.51.100.0-198.51.100.255"]},
        {"svc-one": {"tcp": ["80"]}, "svc-two": {"tcp": ["9000-9100"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-low", "svc-one"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-low", "svc-two", "deny"),
        _entry(3, "zone-hq-core", "zone-dmz-edge", "addr-low", "svc-one", "deny"),
        _entry(4, "zone-hq-core", "zone-dmz-edge", "addr-all", "svc-one", "permit"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-37", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert len(_rows(rules_path)) == 3
    assert _report(report_path)["dropped"] == [{"seq": 3, "shadowed_by": [1]}]
    assert list(_report(report_path)["dropped"][0]) == ["seq", "shadowed_by"]
    assert _report(report_path)["entries"] == 4
    assert _report(report_path)["rules"] == 3


def test_report_lists_split_entries_with_row_counts(tmp_path):
    """题面「是被更早的条目盖住一部分的条目，不管拆成几行都记在这里」：拆分清单。"""
    objects = _objects(
        {"addr-low": ["198.51.100.0/25"], "addr-all": ["198.51.100.0-198.51.100.255"]},
        {"svc-one": {"tcp": ["80"]}},
    )
    ledger = [
        _entry(1, "zone-hq-core", "zone-dmz-edge", "addr-low", "svc-one"),
        _entry(2, "zone-hq-core", "zone-dmz-edge", "addr-all", "svc-one", "deny"),
    ]
    finished, rules_path, report_path = _compile(tmp_path, "case-38", ledger, objects)
    assert finished.returncode == 0, finished.stderr
    assert _report(report_path)["split"] == [{"seq": 2, "lines": 1, "shadowed_by": [1]}]
    assert list(_report(report_path)["split"][0]) == ["seq", "lines", "shadowed_by"]
    assert _report(report_path)["dropped"] == []
    assert _seqs(rules_path) == ["1", "2"]


def test_outputs_go_to_the_two_given_paths(tmp_path):
    """题面「报表跟规则集放在同一个目录」以外的情形：两个路径各写各的产物。"""
    rules_path = tmp_path / "device-a" / "edge-rules.txt"
    report_path = tmp_path / "audit" / "edge-report.json"
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    finished, rules, report = _run_compiler(
        tmp_path / "work",
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
    )
    assert finished.returncode == 0, finished.stderr
    assert _rows(rules) == [SIMPLE_ROW]
    assert _report(report)["rules"] == 1
    assert sorted(item.name for item in (tmp_path / "audit").iterdir()) == ["edge-report.json"]


def test_failed_compile_keeps_previous_artifacts(tmp_path):
    """题面「规则集和报表那两个输出路径上的旧文件一个字节都不动」：拒收时上一版原样留着。"""
    work = tmp_path / "device"
    work.mkdir(parents=True, exist_ok=True)
    rules_path = work / "rules.txt"
    report_path = work / "report.json"
    rules_path.write_bytes(b"PREVIOUS-RULES\n")
    report_path.write_bytes(b"PREVIOUS-REPORT\n")
    ledger = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-nowhere", "svc-one")]
    finished, _, _ = _run_compiler(work, _ledger_text(ledger), _objects_text(SIMPLE_OBJECTS))
    assert _rejection_kept_outputs(finished)
    assert rules_path.read_bytes() == b"PREVIOUS-RULES\n"
    assert report_path.read_bytes() == b"PREVIOUS-REPORT\n"
    assert sorted(item.name for item in work.iterdir()) == ["ledger.json", "objects.json", "report.json", "rules.txt"]


def test_rejected_ledger_keeps_previous_artifacts(tmp_path):
    """题面「作废时脚本非零退出，规则集和报表那两个输出路径上的旧文件一个字节都不动」。"""
    work = tmp_path / "device"
    work.mkdir(parents=True, exist_ok=True)
    rules_path = work / "rules.txt"
    report_path = work / "report.json"
    rules_path.write_bytes(b"PREVIOUS-RULES\n")
    report_path.write_bytes(b"PREVIOUS-REPORT\n")
    ledger = [_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-one", "svc-one", "reject")]
    finished, _, _ = _run_compiler(work, _ledger_text(ledger), _objects_text(SIMPLE_OBJECTS))
    assert _rejection_kept_outputs(finished)
    assert rules_path.read_bytes() == b"PREVIOUS-RULES\n"
    assert report_path.read_bytes() == b"PREVIOUS-REPORT\n"


def test_repeated_compile_writes_identical_bytes(tmp_path):
    """题面「同一份台账重复编译两次，两次的产物要一模一样」：两次产物逐字节相同。"""
    first, rules_first, report_first = _compile(tmp_path, "case-39", SIMPLE_LEDGER, SIMPLE_OBJECTS)
    second, rules_second, report_second = _compile(tmp_path, "case-40", SIMPLE_LEDGER, SIMPLE_OBJECTS)
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert rules_first.read_bytes() == rules_second.read_bytes()
    assert report_first.read_bytes() == report_second.read_bytes()


def test_shipped_ledger_compiles_to_expected_rule_rows(tmp_path):
    """题面「编译出来的结果要能直接下发」：随题台账的规则集逐行落定。"""
    finished, rules_path, _ = _run_compiler(
        tmp_path / "shipped",
        (DATA / "policy-ledger.json").read_text(encoding="utf-8"),
        (DATA / "objects.json").read_text(encoding="utf-8"),
    )
    assert finished.returncode == 0, finished.stderr
    assert _program_lines(rules_path) == SHIPPED_RULE_ROWS + [TRAILER]


def test_shipped_ledger_reports_expected_conflicts(tmp_path):
    """题面「审计拿着报表和规则集能逐行对上」：随题台账的冲突报表落定。"""
    finished, rules_path, report_path = _run_compiler(
        tmp_path / "shipped-report",
        (DATA / "policy-ledger.json").read_text(encoding="utf-8"),
        (DATA / "objects.json").read_text(encoding="utf-8"),
    )
    assert finished.returncode == 0, finished.stderr
    assert _report(report_path) == SHIPPED_REPORT
    assert len(_rows(rules_path)) == SHIPPED_REPORT["rules"]


def test_first_compile_appends_one_dispatch_record(tmp_path):
    """题面「一行一笔落账」：第一次编译在流水上留下这一笔，摘要与产物对得上。"""
    work = tmp_path / "dispatch-edge-a1"
    rules_path, report_path, journal_path = _dispatch_paths(work)
    ledger_text = _ledger_text(SIMPLE_LEDGER)
    finished, rules, _ = _run_compiler(
        work,
        ledger_text,
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert finished.returncode == 0, finished.stderr
    records = _journal_records(journal_path)
    assert len(records) == 1
    assert list(records[0]) == ["site", "ledger_sha256", "rules_sha256", "rules", "prev_sha256"]
    assert records[0]["site"] == "edge-a1"
    assert records[0]["ledger_sha256"] == hashlib.sha256(ledger_text.encode("utf-8")).hexdigest()
    assert records[0]["rules_sha256"] == hashlib.sha256(rules.read_bytes()).hexdigest()
    assert records[0]["rules"] == 1
    assert records[0]["prev_sha256"] == "0" * 64


def test_second_record_chains_to_previous_line(tmp_path):
    """题面「新添的一笔要接在上一笔后面」：第二笔的上一笔摘要指向第一行。"""
    work = tmp_path / "dispatch-edge-a1"
    rules_path, report_path, journal_path = _dispatch_paths(work)
    first, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert first.returncode == 0, first.stderr
    second_ledger = _ledger_text([_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-two", "svc-one")])
    second_objects = _objects_text(_objects({"addr-two": ["198.18.40.0/24"]}, {"svc-one": {"tcp": ["80"]}}))
    second, _, _ = _run_compiler(
        work,
        second_ledger,
        second_objects,
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert second.returncode == 0, second.stderr
    lines = _program_lines(journal_path)
    records = _journal_records(journal_path)
    assert len(records) == 2
    assert records[1]["prev_sha256"] == hashlib.sha256((lines[0] + "\n").encode("utf-8")).hexdigest()


def test_broken_journal_chain_rejects_batch(tmp_path):
    """题面「`prev_sha256` 对不上前一笔，这本账就是断的，整批不发」：断链整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    broken = (
        '{"site":"edge-a1","ledger_sha256":"%s","rules_sha256":"%s","rules":1,'
        '"prev_sha256":"%s"}\n' % ("1" * 64, "2" * 64, "9" * 64)
    )
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert not report_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken


def test_rejects_journal_line_with_surrounding_space(tmp_path):
    """流水行必须是紧凑 JSON；行首或行尾多空格也算账本不合规。"""
    first, rules, report = _compile(tmp_path, "journal-space", SIMPLE_LEDGER, SIMPLE_OBJECTS)
    assert first.returncode == 0
    journal = first.journal_path
    journal.write_bytes(b" " + journal.read_bytes().rstrip(b"\n") + b" \n")
    changed = journal.read_bytes()
    second, rules2, report2 = _run_compiler(
        _work_dir(tmp_path, "journal-space-2"),
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        journal_path=journal,
    )
    assert _rejection_kept_outputs(second)
    assert not rules2.exists()
    assert not report2.exists()
    assert journal.read_bytes() == changed


def test_recorded_ledger_is_not_appended_again(tmp_path):
    """题面「同一份台账（流水里已经有同样的台账摘要）再编译一次，不再添第二笔」：这本账一个字都不动。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    ledger_text = _ledger_text(SIMPLE_LEDGER)
    digest = hashlib.sha256(ledger_text.encode("utf-8")).hexdigest()
    previous = (
        '{"site":"edge-a1","ledger_sha256":"%s","rules_sha256":"%s","rules":1,'
        '"prev_sha256":"%s"}\n' % (digest, "0" * 64, "0" * 64)
    )
    journal_path.write_text(previous, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        ledger_text,
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert finished.returncode == 0, finished.stderr
    assert journal_path.read_text(encoding="utf-8") == previous


def test_new_ledger_appends_record_and_keeps_older_bytes(tmp_path):
    """题面「这本账只往后添。文件里已经躺着的行一个字都不许改」：换台账只往后追加。"""
    work = tmp_path / "dispatch-edge-a1"
    rules_path, report_path, journal_path = _dispatch_paths(work)
    first, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert first.returncode == 0, first.stderr
    after_first = journal_path.read_text(encoding="utf-8")
    second_ledger = _ledger_text([_entry(1, "zone-hq-core", "zone-dmz-edge", "addr-two", "svc-one")])
    second_objects = _objects_text(_objects({"addr-two": ["198.18.40.0/24"]}, {"svc-one": {"tcp": ["80"]}}))
    second, _, _ = _run_compiler(
        work,
        second_ledger,
        second_objects,
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert second.returncode == 0, second.stderr
    after_second = journal_path.read_text(encoding="utf-8")
    assert after_second.startswith(after_first)
    records = _journal_records(journal_path)
    assert len(records) == 2
    assert records[1]["ledger_sha256"] == hashlib.sha256(second_ledger.encode("utf-8")).hexdigest()


def test_journal_record_from_another_device_rejects_batch(tmp_path):
    """题面「流水里混着别的设备的落账」：整批作废，规则集和报表都不落盘。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    foreign = (
        '{"site":"edge-b2","ledger_sha256":"%s","rules_sha256":"%s","rules":41,'
        '"prev_sha256":"%s"}\n' % ("1" * 64, "2" * 64, "0" * 64)
    )
    journal_path.write_text(foreign, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert not report_path.exists()
    assert journal_path.read_text(encoding="utf-8") == foreign


def test_journal_record_missing_key_rejects_batch(tmp_path):
    """题面「键不全、多键」：落账少一个键就整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    broken = '{"site":"edge-a1","ledger_sha256":"%s","rules":41}\n' % ("3" * 64,)
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert not report_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken


def test_journal_record_with_extra_key_rejects_batch(tmp_path):
    """题面「或者某一行不是一本合规的落账」：落账多带一个键也整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    broken = (
        '{"site":"edge-a1","ledger_sha256":"%s","rules_sha256":"%s","rules":41,'
        '"prev_sha256":"%s","note":"x"}\n' % ("3" * 64, "4" * 64, "0" * 64)
    )
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert not report_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken


def test_journal_record_with_malformed_digest_rejects_batch(tmp_path):
    """题面「台账摘要或者规则集摘要不是六十四位小写十六进制」：摘要形状不对就整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    broken = (
        '{"site":"edge-a1","ledger_sha256":"%s","rules_sha256":"%s","rules":41,'
        '"prev_sha256":"%s"}\n' % ("a1b2c3", "4" * 64, "0" * 64)
    )
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken


def test_journal_record_with_whitespace_device_name_rejects_batch(tmp_path):
    """题面「设备名写空或者带空白字符」：落账里的设备名夹了空白就整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path = work / "edge a1.txt"
    report_path = work / "edge a1-report.json"
    journal_path = work / "journal.jsonl"
    broken = (
        '{"site":"edge a1","ledger_sha256":"%s","rules_sha256":"%s","rules":41,'
        '"prev_sha256":"%s"}\n' % ("5" * 64, "6" * 64, "0" * 64)
    )
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken


def test_journal_record_with_bad_rule_count_rejects_batch(tmp_path):
    """题面「条目数不是非负整数」：落账里的条目数不是非负整数的流水整批作废。"""
    work = tmp_path / "dispatch-edge-a1"
    work.mkdir(parents=True, exist_ok=True)
    rules_path, report_path, journal_path = _dispatch_paths(work)
    broken = (
        '{"site":"edge-a1","ledger_sha256":"%s","rules_sha256":"%s","rules":"41",'
        '"prev_sha256":"%s"}\n' % ("7" * 64, "8" * 64, "0" * 64)
    )
    journal_path.write_text(broken, encoding="utf-8")
    finished, _, _ = _run_compiler(
        work,
        _ledger_text(SIMPLE_LEDGER),
        _objects_text(SIMPLE_OBJECTS),
        rules_path=rules_path,
        report_path=report_path,
        journal_path=journal_path,
    )
    assert _rejection_kept_outputs(finished)
    assert not rules_path.exists()
    assert journal_path.read_text(encoding="utf-8") == broken
