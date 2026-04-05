import ipaddress
from dataclasses import dataclass
from typing import Dict, List


# Edit these values for your network and target device.
USER_CONFIG = {
    "TARGET_MACS": [],
    "TARGET_IPS": ["192.168.2.76"],
    "TARGET_HOSTNAMES": [],
    "SUBNET_CIDR": "192.168.2.0/24",
    "POLL_INTERVAL_SECONDS": 20,
    "COMMAND_TIMEOUT_SECONDS": 8,
    "ENABLE_REVERSE_DNS": True,
    "ENABLE_ARP_FALLBACK": True,
    "ENABLE_NMAP_FALLBACK": True,
    "ENABLE_SPEEDPORT_FALLBACK": True,
    "BIND_HOST": "0.0.0.0",
    "BIND_PORT": 5151,
}


def _clean_string_list(values: List[str]) -> List[str]:
    cleaned = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            cleaned.append(text)
    return cleaned


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def _normalize_host(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


@dataclass
class AppConfig:
    target_macs: List[str]
    target_ips: List[str]
    target_hostnames: List[str]
    subnet_cidr: str
    polling_interval_seconds: int
    command_timeout_seconds: int
    enable_reverse_dns: bool
    enable_arp_fallback: bool
    enable_nmap_fallback: bool
    enable_speedport_fallback: bool
    bind_host: str
    bind_port: int

    @property
    def has_targets(self) -> bool:
        return bool(self.target_macs or self.target_ips or self.target_hostnames)

    @property
    def target_summary(self) -> Dict[str, List[str]]:
        return {
            "macs": self.target_macs,
            "ips": self.target_ips,
            "hostnames": self.target_hostnames,
        }


def load_config() -> AppConfig:
    subnet_cidr = str(USER_CONFIG["SUBNET_CIDR"]).strip()
    ipaddress.ip_network(subnet_cidr, strict=False)

    return AppConfig(
        target_macs=[_normalize_mac(item) for item in _clean_string_list(USER_CONFIG["TARGET_MACS"])],
        target_ips=_clean_string_list(USER_CONFIG["TARGET_IPS"]),
        target_hostnames=[_normalize_host(item) for item in _clean_string_list(USER_CONFIG["TARGET_HOSTNAMES"])],
        subnet_cidr=subnet_cidr,
        polling_interval_seconds=max(5, int(USER_CONFIG["POLL_INTERVAL_SECONDS"])),
        command_timeout_seconds=max(2, int(USER_CONFIG["COMMAND_TIMEOUT_SECONDS"])),
        enable_reverse_dns=bool(USER_CONFIG["ENABLE_REVERSE_DNS"]),
        enable_arp_fallback=bool(USER_CONFIG["ENABLE_ARP_FALLBACK"]),
        enable_nmap_fallback=bool(USER_CONFIG["ENABLE_NMAP_FALLBACK"]),
        enable_speedport_fallback=bool(USER_CONFIG["ENABLE_SPEEDPORT_FALLBACK"]),
        bind_host=str(USER_CONFIG["BIND_HOST"]).strip() or "127.0.0.1",
        bind_port=int(USER_CONFIG["BIND_PORT"]),
    )
