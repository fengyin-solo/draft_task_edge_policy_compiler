#!/usr/bin/env python3
"""边界设备的下发编译：把策略台账翻成设备规则集。

这是最早那版脚本，按台账顺序把每条条目的地址对象与服务对象摊到一行上，
写完规则集再补一份报表。台账与对象字典沿用安全组登记的口径。
"""

import ipaddress
import json
import os
import sys

ACTIONS = ("permit", "deny", "translate")
DEFAULT_LINE = "default deny"
MAX_PORT = 65535
PROTOCOLS = ("tcp", "udp")


class UsageError(Exception):
    """参数不对。"""


class LedgerError(Exception):
    """台账或对象字典不符合登记口径。"""


def load_json(path, label):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise LedgerError("%s 读不出来：%s" % (label, exc))


def parse_ipv4(text):
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise LedgerError("%s 不是点分地址" % (text,))
    if address.version != 4:
        raise LedgerError("%s 不是点分地址" % (text,))
    return int(address)


def parse_network(text):
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise LedgerError("%s 不是 CIDR" % (text,))
    return int(network.network_address), int(network.broadcast_address)


def address_item(item):
    if isinstance(item, str) and "-" in item:
        left, right = item.split("-", 1)
        low = parse_ipv4(left)
        high = parse_ipv4(right)
        if low > high:
            raise LedgerError("地址项 %s 前后写反了" % (item,))
        return low, high
    return parse_network(item)


def port_item(item):
    if isinstance(item, bool):
        raise LedgerError("端口项 %r 不是整数" % (item,))
    if isinstance(item, int):
        low = high = item
    elif "-" in item:
        left, right = item.split("-", 1)
        low = int(left)
        high = int(right)
    else:
        low = high = int(item)
    if low < 0 or high > MAX_PORT:
        raise LedgerError("端口项 %r 超出范围" % (item,))
    if low > high:
        raise LedgerError("端口项 %r 前后写反了" % (item,))
    return low, high


def format_ip(value):
    return str(ipaddress.IPv4Address(value))


def format_span(low, high):
    if low == high:
        return format_ip(low)
    return "%s-%s" % (format_ip(low), format_ip(high))


def format_port(low, high):
    if low == high:
        return str(low)
    return "%d-%d" % (low, high)


def load_objects(path):
    raw = load_json(path, "对象字典")
    if not isinstance(raw, dict) or set(raw) != {"address_objects", "service_objects"}:
        raise LedgerError("对象字典顶层键不对")
    addresses = {}
    for name, items in raw["address_objects"].items():
        if not isinstance(items, list) or not items:
            raise LedgerError("地址对象 %s 至少要有一个地址项" % (name,))
        addresses[name] = [address_item(item) for item in items]
    services = {}
    for name, service in raw["service_objects"].items():
        if not isinstance(service, dict) or not service:
            raise LedgerError("服务对象 %s 至少要有一个协议" % (name,))
        expanded = {}
        for protocol, items in service.items():
            if protocol not in PROTOCOLS:
                raise LedgerError("服务对象 %s 里的协议名不认识" % (name,))
            if not isinstance(items, list) or not items:
                raise LedgerError("服务对象 %s 的 %s 至少要有一个端口项" % (name, protocol))
            expanded[protocol] = [port_item(item) for item in items]
        services[name] = expanded
    return addresses, services


def load_ledger(path):
    raw = load_json(path, "台账")
    if not isinstance(raw, list):
        raise LedgerError("台账顶层必须是数组")
    entries = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            raise LedgerError("台账条目必须是对象")
        seq = item["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise LedgerError("序号必须是整数")
        if seq in seen:
            raise LedgerError("序号 %r 重复" % (seq,))
        seen.add(seq)
        action = item["action"]
        if action not in ACTIONS:
            raise LedgerError("动作名 %r 不认识" % (action,))
        if action == "translate" and "translate_to" not in item:
            raise LedgerError("序号 %r 是地址转换，缺少 translate_to" % (seq,))
        if action != "translate" and "translate_to" in item:
            raise LedgerError("序号 %r 不是地址转换，却带着 translate_to" % (seq,))
        entry = {
            "seq": seq,
            "src_zone": item["src_zone"],
            "dst_zone": item["dst_zone"],
            "address": item["address"],
            "service": item["service"],
            "action": action,
        }
        if not entry["src_zone"] or not entry["dst_zone"]:
            raise LedgerError("序号 %r 的区对写空了" % (seq,))
        if action == "translate":
            entry["translate_spans"] = [address_item(item["translate_to"])]
        entries.append(entry)
    return entries


def compile_rules(entries, addresses, services):
    lines = []
    registered = set()
    for entry in entries:
        if entry["address"] not in addresses or entry["service"] not in services:
            continue
        key = (entry["address"], entry["service"])
        if key in registered:
            continue
        registered.add(key)
        for protocol in services[entry["service"]]:
            for port in services[entry["service"]][protocol]:
                for span in addresses[entry["address"]]:
                    parts = [
                        str(entry["seq"]),
                        entry["action"],
                        entry["src_zone"],
                        entry["dst_zone"],
                        protocol,
                        format_port(port[0], port[1]),
                        format_span(span[0], span[1]),
                    ]
                    if entry["action"] == "translate":
                        target = entry["translate_spans"][0]
                        parts.append("->")
                        parts.append(format_span(target[0], target[1]))
                    lines.append(" ".join(parts))
    return sorted(lines)


def device_name(rules_path):
    name = os.path.basename(rules_path)
    return os.path.splitext(name)[0] or name


def main(argv):
    if len(argv) != 6:
        sys.stderr.write(
            "用法: compile_firewall_policy.py <台账> <对象字典> <规则集输出> <报表输出> <下发流水>\n"
        )
        return 2
    try:
        addresses, services = load_objects(argv[2])
        entries = load_ledger(argv[1])
        lines = compile_rules(entries, addresses, services)
    except LedgerError as exc:
        sys.stderr.write("台账不合规：%s\n" % (exc,))
        return 1
    text = "".join(line + "\n" for line in lines + [DEFAULT_LINE])
    report = {"entries": len(entries), "rules": len(lines), "dropped": [], "split": []}
    with open(argv[3], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    with open(argv[4], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n")
    record = {"site": device_name(argv[3]), "rules": len(lines)}
    with open(argv[5], "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
