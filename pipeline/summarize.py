# Шаг суммаризации: IP -> минимальный набор CIDR.
# Базовая механика — collapse_addresses (stdlib ipaddress); группировка по ASN
# (как в step6 Re-filter): IP разных автономок не сливаются между собой,
# чтобы одна большая подсеть одного ASN не «поглощала» чужие адреса.

from __future__ import annotations

import ipaddress


def normalize_to_networks(values: list[str]) -> list:
    """Строки IP/CIDR -> уникальные ip_network (bare IP -> /32 или /128)."""
    networks: dict = {}
    for value in values:
        value = value.strip()
        if not value:
            continue
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
            else:
                addr = ipaddress.ip_address(value)
                net = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            continue  # мусор пропускаем молча: его отсекает ещё collect
        networks[net] = net
    return list(networks)


def summarize(ips: list[str], asn_map: dict | None = None) -> tuple:
    """Суммаризирует IP в CIDR с учётом ASN.

    asn_map: {ip: [asn, aso]} из resolve.annotate_asn. IP без аннотации попадают
    в общую группу None и сливаются только между собой.
    Возвращает (список CIDR-строк, отчёт dict).
    """
    asn_map = asn_map or {}
    groups: dict = {}
    names: dict = {}
    for net in normalize_to_networks(ips):
        ip_str = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        asn = (asn_map.get(ip_str) or asn_map.get(str(net.network_address)) or [None])[0]
        groups.setdefault(asn, []).append(net)
        if asn is not None:
            names[asn] = (asn_map.get(ip_str) or asn_map.get(str(net.network_address)))[1]

    cidrs: list[str] = []
    report: dict = {"input_ips": len(ips), "output_cidrs": 0, "groups": {}, "unattributed": 0}
    for asn, nets in groups.items():
        collapsed = list(ipaddress.collapse_addresses(nets))
        cidrs.extend(str(c) for c in collapsed)
        if asn is None:
            report["unattributed"] = len(nets)
            report["groups"]["unknown"] = {"ips": len(nets), "cidrs": len(collapsed)}
        else:
            report["groups"][str(asn)] = {"ips": len(nets), "cidrs": len(collapsed), "name": names.get(asn)}
    cidrs.sort(key=lambda c: ipaddress.ip_network(c))
    report["output_cidrs"] = len(cidrs)
    report["groups_count"] = len(groups)
    return cidrs, report
