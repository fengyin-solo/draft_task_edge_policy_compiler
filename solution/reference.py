#!/usr/bin/env python3
"""边界策略台账的下发编译。

把安全组维护的策略台账与对象字典编译成设备规则集与冲突报表：先按首个匹配
语义算出每条台账条目还剩下多少覆盖范围，再把剩下的范围展开成设备能表达的
一条条规则，最后写出规则集与报表。失败时一个字节都不落盘。
"""

import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile

ACTIONS = ("permit", "deny", "translate")
JOURNAL_KEYS = ("site", "ledger_sha256", "rules_sha256", "rules", "prev_sha256")
ZERO_DIGEST = "0" * 64
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
ENTRY_KEYS = ("seq", "src_zone", "dst_zone", "address", "service", "action")
TRANSLATE_FIELD = "translate_to"
OBJECT_KEYS = ("address_objects", "service_objects")
PROTOCOLS = ("tcp", "udp")
MAX_PORT = 65535
DEFAULT_LINE = "default deny"


class LedgerError(Exception):
    """台账、对象字典或参数不符合公开契约。"""


def _reject_duplicate_keys(label):
    def hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise LedgerError("%s 里 %s 出现了两次" % (label, key))
            seen.add(key)
        return dict(pairs)

    return hook


def load_json(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except UnicodeDecodeError as exc:
        raise LedgerError("%s 不是 UTF-8：%s" % (label, exc))
    except OSError as exc:
        raise LedgerError("%s 读不出来：%s" % (label, exc))
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys(label))
    except json.JSONDecodeError as exc:
        raise LedgerError("%s 不是合法 JSON：%s" % (label, exc))


def parse_ipv4(text, label):
    if not isinstance(text, str) or not text:
        raise LedgerError("%s 必须是非空字符串" % label)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise LedgerError("%s 不是合法的点分地址：%r" % (label, text))
    if address.version != 4:
        raise LedgerError("%s 不是四段点分地址：%r" % (label, text))
    return int(address)


def parse_network(text, label):
    if not isinstance(text, str) or not text:
        raise LedgerError("%s 必须是非空字符串" % label)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise LedgerError("%s 不是合法的 CIDR：%r" % (label, text))
    if network.version != 4:
        raise LedgerError("%s 不是四段点分地址：%r" % (label, text))
    return int(network.network_address), int(network.broadcast_address)


def parse_address_item(text, label):
    if not isinstance(text, str) or not text:
        raise LedgerError("%s 的地址项必须是非空字符串" % label)
    if "-" in text:
        parts = text.split("-")
        if len(parts) != 2:
            raise LedgerError("%s 的地址项 %r 不是合法的起止区间" % (label, text))
        low = parse_ipv4(parts[0], label)
        high = parse_ipv4(parts[1], label)
        if low > high:
            raise LedgerError("%s 的地址项 %r 前后写反了" % (label, text))
        return low, high
    return parse_network(text, label)


def parse_port_item(text, label):
    if isinstance(text, bool):
        raise LedgerError("%s 的端口项不能是布尔值" % label)
    if isinstance(text, int):
        low = high = text
    elif isinstance(text, str) and "-" in text:
        parts = text.split("-")
        if len(parts) != 2:
            raise LedgerError("%s 的端口项 %r 不是合法的区间" % (label, text))
        low = parse_port_number(parts[0], label)
        high = parse_port_number(parts[1], label)
    else:
        low = high = parse_port_number(text, label)
    if low < 0 or high > MAX_PORT:
        raise LedgerError("%s 的端口项超出 0 到 %d" % (label, MAX_PORT))
    if low > high:
        raise LedgerError("%s 的端口项前后写反了" % label)
    return low, high


def parse_port_number(text, label):
    if isinstance(text, bool) or not isinstance(text, (int, str)):
        raise LedgerError("%s 的端口项 %r 不是整数" % (label, text))
    if isinstance(text, str):
        if not text.isdigit():
            raise LedgerError("%s 的端口项 %r 不是整数" % (label, text))
        return int(text)
    return text


def merge_spans(spans):
    merged = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1] + 1:
            if high > merged[-1][1]:
                merged[-1] = (merged[-1][0], high)
        else:
            merged.append((low, high))
    return merged


def spans_overlap(left, right):
    for low, high in left:
        for other_low, other_high in right:
            if low <= other_high and other_low <= high:
                return True
    return False


def subtract_spans(spans, removed):
    result = []
    holes = merge_spans(removed)
    for low, high in spans:
        cursor = low
        for hole_low, hole_high in holes:
            if hole_high < cursor or hole_low > high:
                continue
            if hole_low > cursor:
                result.append((cursor, min(hole_low - 1, high)))
            cursor = max(cursor, hole_high + 1)
            if cursor > high:
                break
        if cursor <= high:
            result.append((cursor, high))
    return result


def format_ip(value):
    return str(ipaddress.IPv4Address(value))


def format_span(low, high):
    if low == high:
        return format_ip(low)
    return "%s-%s" % (format_ip(low), format_ip(high))


def format_port_span(low, high):
    if low == high:
        return str(low)
    return "%d-%d" % (low, high)


def file_digest(path, label):
    try:
        with open(path, "rb") as handle:
            payload = handle.read()
    except OSError as exc:
        raise LedgerError("%s 读不出来：%s" % (label, exc))
    return hashlib.sha256(payload).hexdigest()


def device_name(rules_path):
    name = os.path.basename(rules_path)
    stem = os.path.splitext(name)[0]
    return stem or name


def check_journal_record(record, number, device):
    if not isinstance(record, dict):
        raise LedgerError("流水第 %d 行不是一本合规的落账" % (number,))
    for key in JOURNAL_KEYS:
        if key not in record:
            raise LedgerError("流水第 %d 行不是一本合规的落账" % (number,))
    if any(key not in JOURNAL_KEYS for key in record):
        raise LedgerError("流水第 %d 行不是一本合规的落账" % (number,))
    site = record["site"]
    if not isinstance(site, str) or not site or any(char.isspace() for char in site):
        raise LedgerError("流水第 %d 行的设备名不合规" % (number,))
    if site != device:
        raise LedgerError("流水第 %d 行是别的设备的落账：%s" % (number, site))
    for key in ("ledger_sha256", "rules_sha256", "prev_sha256"):
        value = record[key]
        if not isinstance(value, str) or not DIGEST_PATTERN.match(value):
            raise LedgerError("流水第 %d 行的 %s 不是六十四位小写十六进制" % (number, key))
    count = record["rules"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise LedgerError("流水第 %d 行的条目数不是非负整数" % (number,))
    return record


def line_digest(line):
    return hashlib.sha256((line + "\n").encode("utf-8")).hexdigest()


def load_journal(path, device):
    if not os.path.exists(path):
        return [], ZERO_DIGEST
    try:
        with open(path, "rb") as handle:
            payload = handle.read()
    except OSError as exc:
        raise LedgerError("流水读不出来：%s" % (exc,))
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LedgerError("流水不是 UTF-8：%s" % (exc,))
    records = []
    tail = ZERO_DIGEST
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=_reject_duplicate_keys("流水第 %d 行" % (number,)))
        except json.JSONDecodeError as exc:
            raise LedgerError("流水第 %d 行不是合法 JSON：%s" % (number, exc))
        checked = check_journal_record(record, number, device)
        if checked["prev_sha256"] != tail:
            raise LedgerError("流水第 %d 行接不上上一笔的摘要" % (number,))
        records.append(checked)
        tail = line_digest(line)
    return records, tail


def append_journal(path, records, device, ledger_digest, rule_text, tail):
    if any(record["ledger_sha256"] == ledger_digest for record in records):
        return
    entry = {
        "site": device,
        "ledger_sha256": ledger_digest,
        "rules_sha256": hashlib.sha256(rule_text.encode("utf-8")).hexdigest(),
        "rules": rule_text.count("\n") - 1,
        "prev_sha256": tail,
    }
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")


def load_address_objects(raw):
    objects = {}
    for name, items in raw.items():
        if not isinstance(name, str) or not name:
            raise LedgerError("地址对象的名字必须是非空字符串")
        if not isinstance(items, list) or not items:
            raise LedgerError("地址对象 %s 至少要有一个地址项" % (name,))
        spans = merge_spans(parse_address_item(item, name) for item in items)
        objects[name] = spans
    return objects


def load_service_objects(raw):
    objects = {}
    for name, service in raw.items():
        if not isinstance(name, str) or not name:
            raise LedgerError("服务对象的名字必须是非空字符串")
        if not isinstance(service, dict) or not service:
            raise LedgerError("服务对象 %s 至少要有一个协议" % (name,))
        protocols = {}
        for protocol, items in service.items():
            if protocol not in PROTOCOLS:
                raise LedgerError("服务对象 %s 里的协议名 %r 不是 tcp 也不是 udp" % (name, protocol))
            if not isinstance(items, list) or not items:
                raise LedgerError("服务对象 %s 的 %s 至少要有一个端口项" % (name, protocol))
            protocols[protocol] = merge_spans(parse_port_item(item, name) for item in items)
        objects[name] = protocols
    return objects


def load_objects(path):
    raw = load_json(path, "对象字典")
    if not isinstance(raw, dict):
        raise LedgerError("对象字典顶层必须是一个对象")
    if set(raw) != set(OBJECT_KEYS):
        raise LedgerError("对象字典顶层的键只能是 %s" % ("、".join(OBJECT_KEYS),))
    for key in OBJECT_KEYS:
        if not isinstance(raw[key], dict) or not raw[key]:
            raise LedgerError("对象字典的 %s 必须是非空对象" % (key,))
    return load_address_objects(raw["address_objects"]), load_service_objects(raw["service_objects"])


def zone_name(value, label):
    if not isinstance(value, str) or not value:
        raise LedgerError("%s 必须是非空字符串" % label)
    if any(char.isspace() for char in value):
        raise LedgerError("%s 里不能带空白字符" % label)
    return value


def load_ledger(path):
    raw = load_json(path, "台账")
    if not isinstance(raw, list):
        raise LedgerError("台账顶层必须是一个数组")
    entries = []
    for index, item in enumerate(raw, 1):
        entries.append(check_entry(item, index))
    numbers = [entry["seq"] for entry in entries]
    if len(set(numbers)) != len(numbers):
        raise LedgerError("台账里有重复的序号")
    distinct = sorted(set(numbers))
    if distinct != list(range(1, len(distinct) + 1)):
        raise LedgerError("台账的序号跳号了")
    if numbers != sorted(numbers):
        raise LedgerError("台账的数组顺序与序号对不上")
    return entries


def check_entry(item, index):
    if not isinstance(item, dict):
        raise LedgerError("台账第 %d 条必须是一个对象" % (index,))
    for key in ENTRY_KEYS:
        if key not in item:
            raise LedgerError("台账第 %d 条缺少 %s" % (index, key))
    action = item["action"]
    if action not in ACTIONS:
        raise LedgerError("台账第 %d 条的动作名 %r 不认识" % (index, action))
    allowed = set(ENTRY_KEYS)
    if action == "translate":
        allowed.add(TRANSLATE_FIELD)
        if TRANSLATE_FIELD not in item:
            raise LedgerError("台账第 %d 条是地址转换，缺少 %s" % (index, TRANSLATE_FIELD))
    elif TRANSLATE_FIELD in item:
        raise LedgerError("台账第 %d 条的动作不是地址转换，不能带 %s" % (index, TRANSLATE_FIELD))
    extra = sorted(set(item) - allowed)
    if extra:
        raise LedgerError("台账第 %d 条多出了 %s" % (index, "、".join(extra)))
    seq = item["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise LedgerError("台账第 %d 条的序号不是整数" % (index,))
    entry = {
        "seq": seq,
        "src_zone": zone_name(item["src_zone"], "台账第 %d 条的源区" % (index,)),
        "dst_zone": zone_name(item["dst_zone"], "台账第 %d 条的目的区" % (index,)),
        "address": item["address"],
        "service": item["service"],
        "action": action,
    }
    for key in ("address", "service"):
        if not isinstance(entry[key], str) or not entry[key]:
            raise LedgerError("台账第 %d 条的 %s 必须是非空字符串" % (index, key))
    if action == "translate":
        entry["translate_spans"] = merge_spans(
            [parse_address_item(item[TRANSLATE_FIELD], "台账第 %d 条的 %s" % (index, TRANSLATE_FIELD))]
        )
    return entry


def resolve(entry, address_objects, service_objects):
    for key, table in (("address", address_objects), ("service", service_objects)):
        if entry[key] not in table:
            raise LedgerError(
                "台账第 %d 条引用的%s %s 在对象字典里找不到" % (entry["seq"], "地址对象" if key == "address" else "服务对象", entry[key])
            )
    return address_objects[entry["address"]], service_objects[entry["service"]]


def same_coverage(left, right):
    return (
        left["src_zone"] == right["src_zone"]
        and left["dst_zone"] == right["dst_zone"]
        and spans_overlap(left["addresses"], right["addresses"])
        and any(
            protocol in right["services"] and spans_overlap(spans, right["services"][protocol])
            for protocol, spans in left["services"].items()
        )
    )


def blocker_spans(blocker, protocol, low, high):
    spans = blocker["services"].get(protocol)
    if not spans:
        return None
    for span_low, span_high in spans:
        if span_low <= low and high <= span_high:
            return blocker["addresses"]
    return None


def residual_lines(entry, blockers):
    lines = []
    for protocol in sorted(entry["services"]):
        port_spans = entry["services"][protocol]
        cuts = set()
        for low, high in port_spans:
            cuts.add(low)
            cuts.add(high + 1)
        for blocker in blockers:
            for low, high in blocker["services"].get(protocol, []):
                cuts.add(low)
                cuts.add(high + 1)
        slabs = []
        for low, high in port_spans:
            points = sorted(point for point in cuts if low < point <= high)
            start = low
            for point in points:
                slabs.append((start, point - 1))
                start = point
            slabs.append((start, high))
        pending = []
        for start, end in slabs:
            removed = []
            for blocker in blockers:
                spans = blocker_spans(blocker, protocol, start, end)
                if spans:
                    removed.extend(spans)
            remaining = tuple(subtract_spans(entry["addresses"], removed))
            if pending and pending[-1][1] + 1 == start and pending[-1][2] == remaining:
                pending[-1] = (pending[-1][0], end, remaining)
            else:
                pending.append((start, end, remaining))
        for start, end, remaining in pending:
            for low, high in remaining:
                lines.append((protocol, start, end, low, high))
    return sorted(lines, key=lambda item: (item[0], item[1], item[3]))


def render_line(entry, protocol, port_low, port_high, addr_low, addr_high):
    parts = [
        str(entry["seq"]),
        entry["action"],
        entry["src_zone"],
        entry["dst_zone"],
        protocol,
        format_port_span(port_low, port_high),
        format_span(addr_low, addr_high),
    ]
    if entry["action"] == "translate":
        parts.append("->")
        parts.append(format_span(*entry["translate_spans"][0]))
    return " ".join(parts)


def check_translation_targets(resolved):
    for entry in resolved:
        if entry["action"] != "translate":
            continue
        for other in resolved:
            if other["action"] != "translate":
                continue
            if spans_overlap(entry["translate_spans"], other["addresses"]):
                raise LedgerError(
                    "台账第 %d 条的改写目标落在第 %d 条转换条目的匹配地址里，同一个包会被连着改写两次"
                    % (entry["seq"], other["seq"])
                )


def compile_policy(ledger_path, objects_path):
    address_objects, service_objects = load_objects(objects_path)
    entries = load_ledger(ledger_path)
    resolved = []
    for entry in entries:
        addresses, services = resolve(entry, address_objects, service_objects)
        resolved.append(dict(entry, addresses=addresses, services=services))
    check_translation_targets(resolved)

    rule_lines = []
    dropped = []
    split = []
    for index, entry in enumerate(resolved):
        blockers = [
            other for other in resolved[:index] if same_coverage(entry, other)
        ]
        lines = residual_lines(entry, blockers)
        shadowed_by = sorted(other["seq"] for other in blockers)
        if not lines:
            dropped.append({"seq": entry["seq"], "shadowed_by": shadowed_by})
            continue
        if blockers:
            split.append({"seq": entry["seq"], "lines": len(lines), "shadowed_by": shadowed_by})
        for line in lines:
            rule_lines.append(render_line(entry, *line))

    rule_text = "".join(line + "\n" for line in rule_lines + [DEFAULT_LINE])
    report = {
        "entries": len(resolved),
        "rules": len(rule_lines),
        "dropped": dropped,
        "split": split,
    }
    report_text = json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n"
    return rule_text, report_text


def write_outputs(targets):
    staged = []
    try:
        for path, text in targets:
            directory = os.path.dirname(os.path.abspath(path)) or "."
            handle, temporary = tempfile.mkstemp(prefix=".edge-policy-", suffix=".part", dir=directory)
            staged.append((temporary, path))
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        for temporary, path in staged:
            os.replace(temporary, path)
        staged = []
    finally:
        for temporary, _ in staged:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def main(argv):
    if len(argv) != 6:
        sys.stderr.write(
            "用法: compile_firewall_policy.py <台账> <对象字典> <规则集输出> <报表输出> <下发流水>\n"
        )
        return 2
    try:
        ledger_digest = file_digest(argv[1], "台账")
        device = device_name(argv[3])
        records, tail = load_journal(argv[5], device)
        rule_text, report_text = compile_policy(argv[1], argv[2])
        write_outputs([(argv[3], rule_text), (argv[4], report_text)])
        append_journal(argv[5], records, device, ledger_digest, rule_text, tail)
    except LedgerError as exc:
        sys.stderr.write("台账不合规：%s\n" % (exc,))
        return 1
    except OSError as exc:
        sys.stderr.write("写不出产物：%s\n" % (exc,))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
