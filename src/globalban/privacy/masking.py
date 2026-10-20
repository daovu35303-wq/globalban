from __future__ import annotations

from ipaddress import ip_address, ip_network


def mask_ip(value: str, ipv4_prefix: int = 24, ipv6_prefix: int = 48) -> str:
    address = ip_address(value)
    prefix = ipv4_prefix if address.version == 4 else ipv6_prefix
    return ip_network(f"{address}/{prefix}", strict=False).with_prefixlen