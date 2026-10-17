#!/usr/bin/env python3
"""生成随题交付的边界策略台账与对象字典。

用法: python3 generate_data.py --out <目录>

台账是安全组这一轮交给边界设备下发的访问策略，对象字典是安全组维护的地址与
服务口径。两份文件都由本脚本按固定内容写出，没有任何随机源。
"""

import argparse
import hashlib
import json
import os

# 地址对象：每个对象是一组地址项，项写成 CIDR 或者起止区间。
ADDRESS_OBJECTS = {
    "addr-dmz-public": ["198.51.100.0/25", "198.51.100.128-198.51.100.255"],
    "addr-dmz-partner": ["203.0.113.64/26", "203.0.113.96-203.0.113.127"],
    "addr-dmz-frontline": ["198.51.100.0/26"],
    "addr-hq-core": ["192.0.2.0/25", "192.0.2.128-192.0.2.191"],
    "addr-payroll-bldg3": ["203.0.113.0/26", "203.0.113.70-203.0.113.80"],
    "addr-payroll-wide": ["203.0.113.0-203.0.113.31", "203.0.113.64-203.0.113.95"],
    "addr-dc-app-a": ["198.18.0.0/24", "198.18.2.0/24"],
    "addr-dc-app-batch": ["198.18.2.0/25", "198.18.2.128/25"],
    "addr-dc-app-next": ["198.18.4.0/24"],
    "addr-dc-db-a": ["192.0.2.192/26", "192.0.2.224-192.0.2.255"],
    "addr-dc-db-wide": ["192.0.2.128/25"],
    "addr-ot-legacy": ["203.0.113.128/25"],
    "addr-vpn-partner-a": ["198.51.100.192/28"],
    "addr-vpn-partner-b": ["198.51.100.192/29"],
    "addr-wifi-guest": ["198.18.8.0/23", "198.18.10.0-198.18.10.127"],
    "addr-mgmt-jump": ["192.0.2.254"],
}

# 服务对象：每个对象以协议名为键，值是端口项，项写成单端口或者端口区间。
SERVICE_OBJECTS = {
    "svc-web-static": {"tcp": ["80", "443"]},
    "svc-web-rollout": {"tcp": ["8080-8090", "8091-8100"]},
    "svc-web-wide": {"tcp": ["8000-8100"]},
    "svc-web-midway": {"tcp": ["8020-8059"]},
    "svc-web-frontline": {"tcp": ["8000-8049"]},
    "svc-dns-egress": {"tcp": ["53"], "udp": ["53"]},
    "svc-ntp-in": {"udp": ["123"]},
    "svc-mgmt-ssh": {"tcp": ["22"]},
    "svc-db-mysql": {"tcp": ["3306"]},
    "svc-smb-legacy": {"tcp": ["139", "445"]},
    "svc-print-legacy": {"tcp": ["515", "631", "632-640"]},
    "svc-app-cluster": {"tcp": ["8443", "9100-9102"], "udp": ["4789"]},
    "svc-ot-mixed": {"tcp": ["515", "10050-10090"], "udp": ["4789"]},
}

# 台账：数组顺序就是下发优先级，seq 从 1 连排。
LEDGER = [
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-public", "svc-web-static", "permit", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-public", "svc-dns-egress", "permit", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-public", "svc-web-rollout", "permit", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-public", "svc-web-static", "deny", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-partner", "svc-web-midway", "deny", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-partner", "svc-web-wide", "permit", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-hq-core", "svc-ntp-in", "permit", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-frontline", "svc-web-frontline", "deny", None),
    ("zone-hq-core", "zone-dmz-edge", "addr-dmz-public", "svc-web-wide", "permit", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-app-a", "svc-web-wide", "permit", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-app-batch", "svc-web-wide", "deny", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-app-a", "svc-web-rollout", "deny", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-app-next", "svc-app-cluster", "permit", None),
    ("zone-ot-legacy", "zone-dc-app", "addr-ot-legacy", "svc-db-mysql", "permit", None),
    ("zone-ot-legacy", "zone-dc-app", "addr-ot-legacy", "svc-db-mysql", "deny", None),
    ("zone-vpn-partner", "zone-dc-app", "addr-vpn-partner-a", "svc-mgmt-ssh", "translate", "198.18.30.0/24"),
    ("zone-vpn-partner", "zone-dc-app", "addr-vpn-partner-b", "svc-mgmt-ssh", "permit", None),
    ("zone-vpn-partner", "zone-dc-app", "addr-vpn-partner-a", "svc-db-mysql", "permit", None),
    ("zone-dmz-edge", "zone-hq-core", "addr-dmz-public", "svc-web-static", "permit", None),
    ("zone-hq-core", "zone-payroll-bldg3", "addr-payroll-bldg3", "svc-smb-legacy", "permit", None),
    ("zone-hq-core", "zone-payroll-bldg3", "addr-payroll-wide", "svc-smb-legacy", "deny", None),
    ("zone-hq-core", "zone-payroll-bldg3", "addr-payroll-wide", "svc-print-legacy", "permit", None),
    ("zone-wifi-guest", "zone-dmz-edge", "addr-wifi-guest", "svc-web-static", "permit", None),
    ("zone-hq-core", "zone-wifi-guest", "addr-wifi-guest", "svc-web-static", "deny", None),
    ("zone-mgmt-plane", "zone-hq-core", "addr-mgmt-jump", "svc-mgmt-ssh", "permit", None),
    ("zone-hq-core", "zone-payroll-bldg3", "addr-payroll-wide", "svc-ntp-in", "translate", "203.0.113.232/29"),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-db-a", "svc-ot-mixed", "deny", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-db-a", "svc-db-mysql", "deny", None),
    ("zone-dmz-edge", "zone-dc-app", "addr-dc-db-wide", "svc-db-mysql", "permit", None),
]


def ledger_entries():
    entries = []
    for number, (src, dst, address, service, action, translate_to) in enumerate(LEDGER, 1):
        entry = {
            "seq": number,
            "src_zone": src,
            "dst_zone": dst,
            "address": address,
            "service": service,
            "action": action,
        }
        if translate_to is not None:
            entry["translate_to"] = translate_to
        entries.append(entry)
    return entries


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# 下发流水上留着的前几笔：设备 edge-a1 上上一轮比对留下的落账。
JOURNAL_SEED = [
    {
        "site": "edge-a1",
        "ledger_sha256": _digest("edge-a1 20261011 台账"),
        "rules_sha256": _digest("edge-a1 20261011 规则集"),
        "rules": 38,
    },
    {
        "site": "edge-a1",
        "ledger_sha256": _digest("edge-a1 20261012 台账"),
        "rules_sha256": _digest("edge-a1 20261012 规则集"),
        "rules": 41,
    },
    {
        "site": "edge-a1",
        "ledger_sha256": _digest("edge-a1 20261013 台账"),
        "rules_sha256": _digest("edge-a1 20261013 规则集"),
        "rules": 44,
    },
]


def journal_text():
    return "".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n" for item in JOURNAL_SEED
    )


SOURCE_NOTE = """这是安全组这一轮交给边界设备下发的访问策略台账与对象字典：
台账里是二十九条按序号排好的条目，覆盖总部到边界、边界到应用区、办公到财务区、
伙伴接入与运维跳板等区对；对象字典是安全组维护的地址与服务口径，地址项按网段或
起止区间登记，服务项按协议下的单端口或端口区间登记。
台账、对象字典和流水上那几笔都由 environment/generate_data.py 这个生成脚本展开，脚本里写的是
固定内容，按种子 20261016 定住，没有随机抽样，重复运行得到逐字节相同的文件。
区对集中在前两个方向，地址对象与服务对象里最常见的几个被反复引用，长尾对象只出现一两次，
和组里实际的登记习惯一致。设备 edge-a1 的下发流水上还留着前面三笔落账，那是上一轮比对时
留下的，也一并由同一个生成脚本写出，构建镜像时会把它放到这台机器的流水位置上。
数据是按安全组的登记口径人工构造的演练数据，不含任何真实网络资产、客户网段或者从别处
搬来的地址清单。
"""


def main():
    parser = argparse.ArgumentParser(description="生成边界策略台账与对象字典")
    parser.add_argument("--out", required=True, help="输出目录")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    documents = (
        ("policy-ledger.json", ledger_entries()),
        ("objects.json", {"address_objects": ADDRESS_OBJECTS, "service_objects": SERVICE_OBJECTS}),
    )
    for name, payload in documents:
        body = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        path = os.path.join(args.out, name)
        with open(path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(body)
    with open(os.path.join(args.out, "dispatch-journal.jsonl"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(journal_text())
    with open(os.path.join(args.out, "DATA_SOURCE.txt"), "w", encoding="utf-8", newline="\n") as stream:
        stream.write(SOURCE_NOTE)


if __name__ == "__main__":
    main()
