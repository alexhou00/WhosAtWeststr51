import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


USER_CONFIG = {
    "TARGETS": [
        {
            "name": "Chanel",
            "macs": ["1E-46-E2-4C-2D-6F"],
            "ips": ["192.168.2.61"],
            "hostnames": [],
        },
        {
            "name": "Jennie",
            "macs": ["1A-3D-4C-EE-2C-B1"],
            "ips": ["192.168.2.38"],
            "hostnames": [],
        },
        {
            "name": "Alex",
            "macs": ["EE-DC-3B-F9-D1-C6"],
            "ips": ["192.168.2.71"],
            "hostnames": [],
        },
    ],
    "SUBNET_CIDR": "192.168.2.0/24",
    "POLL_INTERVAL_SECONDS": 600,
    "COMMAND_TIMEOUT_SECONDS": 8,
    "ENABLE_REVERSE_DNS": True,
    "ENABLE_ARP_FALLBACK": True,
    "ENABLE_NMAP_FALLBACK": True,
    "SPEEDPORT_COMMAND": "",
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


def _resolve_speedport_command(configured_value: str) -> str:
    configured = str(configured_value).strip()
    if configured:
        return configured

    project_root = Path(__file__).resolve().parent
    candidates = [
        project_root / ".venv" / "Scripts" / "speedport.exe",
        project_root / ".venv" / "Scripts" / "speedport.cmd",
        project_root / ".venv" / "Scripts" / "speedport.bat",
        project_root / ".venv" / "Scripts" / "speedport",
        project_root / ".venv" / "bin" / "speedport",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return "speedport"


@dataclass
class TargetConfig:
    name: str
    macs: List[str]
    ips: List[str]
    hostnames: List[str]

    @property
    def has_identifiers(self) -> bool:
        return bool(self.macs or self.ips or self.hostnames)

    def to_summary(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "macs": self.macs,
            "ips": self.ips,
            "hostnames": self.hostnames,
        }


@dataclass
class AppConfig:
    targets: List[TargetConfig]
    subnet_cidr: str
    polling_interval_seconds: int
    command_timeout_seconds: int
    enable_reverse_dns: bool
    enable_arp_fallback: bool
    enable_nmap_fallback: bool
    speedport_command: str
    bind_host: str
    bind_port: int

    @property
    def has_targets(self) -> bool:
        return any(target.has_identifiers for target in self.targets)

    @property
    def target_summary(self) -> List[Dict[str, object]]:
        return [target.to_summary() for target in self.targets]


def _parse_target(raw_target: Dict[str, object]) -> Optional[TargetConfig]:
    name = str(raw_target.get("name", "")).strip()
    if not name:
        return None

    return TargetConfig(
        name=name,
        macs=[_normalize_mac(item) for item in _clean_string_list(raw_target.get("macs", []))],
        ips=_clean_string_list(raw_target.get("ips", [])),
        hostnames=[_normalize_host(item) for item in _clean_string_list(raw_target.get("hostnames", []))],
    )


def load_config() -> AppConfig:
    subnet_cidr = str(USER_CONFIG["SUBNET_CIDR"]).strip()
    ipaddress.ip_network(subnet_cidr, strict=False)

    targets = []
    for raw_target in USER_CONFIG.get("TARGETS", []):
        if not isinstance(raw_target, dict):
            continue
        parsed = _parse_target(raw_target)
        if parsed:
            targets.append(parsed)

    return AppConfig(
        targets=targets,
        subnet_cidr=subnet_cidr,
        polling_interval_seconds=max(5, int(USER_CONFIG["POLL_INTERVAL_SECONDS"])),
        command_timeout_seconds=max(2, int(USER_CONFIG["COMMAND_TIMEOUT_SECONDS"])),
        enable_reverse_dns=bool(USER_CONFIG["ENABLE_REVERSE_DNS"]),
        enable_arp_fallback=bool(USER_CONFIG["ENABLE_ARP_FALLBACK"]),
        enable_nmap_fallback=bool(USER_CONFIG["ENABLE_NMAP_FALLBACK"]),
        speedport_command=_resolve_speedport_command(USER_CONFIG.get("SPEEDPORT_COMMAND", "")),
        bind_host=str(USER_CONFIG["BIND_HOST"]).strip() or "127.0.0.1",
        bind_port=int(USER_CONFIG["BIND_PORT"]),
    )
