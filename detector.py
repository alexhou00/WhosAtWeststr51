import re
import shutil
import socket
import subprocess
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from config import AppConfig


ARP_LINE_RE = re.compile(
    r"^(?P<hostname>\S+)\s+\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>\S+)(?:\s+\[[^\]]+\])?\s+on\s+(?P<interface>\S+)$"
)
NMAP_REPORT_RE = re.compile(r"^Nmap scan report for (?P<target>.+)$")
NMAP_MAC_RE = re.compile(r"^MAC Address:\s+(?P<mac>[0-9A-Fa-f:]{17})")
NEIGH_INACTIVE_STATES = {"FAILED", "INCOMPLETE", "NONE"}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.strip().lower().replace("-", ":")


def _normalize_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    return hostname.strip().lower().rstrip(".")


def _hostname_candidates(hostname: Optional[str]) -> List[str]:
    normalized = _normalize_hostname(hostname)
    if not normalized:
        return []

    candidates = [normalized]
    short_name = normalized.split(".", 1)[0]
    if short_name and short_name not in candidates:
        candidates.append(short_name)
    return candidates


@dataclass
class DeviceObservation:
    source: str
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    interface: Optional[str] = None
    state: Optional[str] = None
    raw: Optional[str] = None

    def is_probably_present(self) -> bool:
        if self.source == "ip neigh":
            if self.state and self.state.upper() in NEIGH_INACTIVE_STATES:
                return False
            return bool(self.ip or self.mac)

        if self.source == "arp -a":
            return bool(self.mac)

        if self.source == "nmap -sn":
            return True

        if self.source == "speedport devices":
            return str(self.state).lower() == "true"

        return bool(self.ip or self.mac)

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "source": self.source,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "interface": self.interface,
            "state": self.state,
            "present_hint": self.is_probably_present(),
            "raw": self.raw,
        }


@dataclass
class MatchResult:
    matched_by: str
    target_identifier: str
    confidence: str
    observation: DeviceObservation


@dataclass
class CommandResult:
    stdout: str
    stderr: str
    returncode: int
    error: Optional[str] = None


class PresenceDetector:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.last_positive_detection: Optional[str] = None

    def get_status(self) -> Dict[str, object]:
        checked_at = _now_iso()

        if not self.config.has_targets:
            return {
                "present": False,
                "status_text": "Configuration needed",
                "last_checked": checked_at,
                "method": "not_configured",
                "matched_by": None,
                "target_identifier": None,
                "confidence": "low",
                "last_positive_detection": self.last_positive_detection,
                "sources_attempted": [],
                "details": [],
                "errors": [
                    "No target MAC, IP, or hostname is configured in config.py."
                ],
            }

        all_devices: List[DeviceObservation] = []
        sources_attempted: List[str] = []
        errors: List[str] = []

        for method_name, devices, method_errors in self._collect_all_sources():
            sources_attempted.append(method_name)
            errors.extend(method_errors)
            all_devices.extend(devices)

            match = self._find_match(devices)
            if match:
                self.last_positive_detection = checked_at
                return {
                    "present": True,
                    "status_text": "Probably at Home",
                    "last_checked": checked_at,
                    "method": match.observation.source,
                    "matched_by": match.matched_by,
                    "target_identifier": match.target_identifier,
                    "confidence": match.confidence,
                    "last_positive_detection": self.last_positive_detection,
                    "sources_attempted": sources_attempted,
                    "details": [item.to_dict() for item in all_devices],
                    "errors": errors,
                }

        method_summary = ", ".join(sources_attempted) if sources_attempted else "no methods ran"
        return {
            "present": False,
            "status_text": "Probably not at Home",
            "last_checked": checked_at,
            "method": method_summary,
            "matched_by": None,
            "target_identifier": None,
            "confidence": "low",
            "last_positive_detection": self.last_positive_detection,
            "sources_attempted": sources_attempted,
            "details": [item.to_dict() for item in all_devices],
            "errors": errors,
        }

    def inspect_devices(self) -> Dict[str, object]:
        checked_at = _now_iso()
        all_devices: List[DeviceObservation] = []
        sources_attempted: List[str] = []
        errors: List[str] = []

        for method_name, devices, method_errors in self._collect_all_sources():
            sources_attempted.append(method_name)
            errors.extend(method_errors)
            all_devices.extend(devices)

        return {
            "checked_at": checked_at,
            "sources_attempted": sources_attempted,
            "targets": self.config.target_summary,
            "errors": errors,
            "devices": [item.to_dict() for item in all_devices],
        }

    def _collect_all_sources(self) -> List[Tuple[str, List[DeviceObservation], List[str]]]:
        results: List[Tuple[str, List[DeviceObservation], List[str]]] = []

        if self.config.enable_speedport_fallback:
            results.append(self._collect_speedport_devices())

        results.append(self._collect_ip_neigh())

        if self.config.enable_arp_fallback:
            results.append(self._collect_arp_table())

        if self.config.enable_nmap_fallback:
            results.append(self._collect_nmap_scan())

        return results

    def _collect_ip_neigh(self) -> Tuple[str, List[DeviceObservation], List[str]]:
        method_name = "ip neigh"
        result = self._run_command(["ip", "neigh"])
        if result.error:
            return method_name, [], [result.error]
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "ip neigh returned a non-zero exit code."
            return method_name, [], [message]

        devices = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_ip_neigh_line(line)
            if parsed:
                devices.append(parsed)

        self._maybe_fill_hostnames(devices)
        return method_name, devices, []

    def _collect_arp_table(self) -> Tuple[str, List[DeviceObservation], List[str]]:
        method_name = "arp -a"
        result = self._run_command(["arp", "-a"])
        if result.error:
            return method_name, [], [result.error]
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "arp -a returned a non-zero exit code."
            return method_name, [], [message]

        devices = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_arp_line(line)
            if parsed:
                devices.append(parsed)

        self._maybe_fill_hostnames(devices)
        return method_name, devices, []

    def _collect_nmap_scan(self) -> Tuple[str, List[DeviceObservation], List[str]]:
        method_name = "nmap -sn"
        if not shutil.which("nmap"):
            return method_name, [], [
                "nmap fallback is enabled, but the nmap command is not installed."
            ]

        result = self._run_command(["nmap", "-sn", self.config.subnet_cidr])
        if result.error:
            return method_name, [], [result.error]
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "nmap -sn returned a non-zero exit code."
            return method_name, [], [message]

        devices = self._parse_nmap_output(result.stdout)
        self._maybe_fill_hostnames(devices)
        return method_name, devices, []

    def _collect_speedport_devices(self) -> Tuple[str, List[DeviceObservation], List[str]]:
        method_name = "speedport devices"
        speedport_command = self.config.speedport_command
        if not self._command_exists(speedport_command):
            return method_name, [], [
                "speedport fallback is enabled, but the configured Speedport command was not found: {0}".format(
                    speedport_command
                )
            ]

        result = self._run_command([speedport_command, "devices"])
        if result.error:
            return method_name, [], [result.error]
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "speedport devices returned a non-zero exit code."
            return method_name, [], [message]

        devices = self._parse_speedport_output(result.stdout)
        return method_name, devices, []

    def _run_command(self, args: List[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.config.command_timeout_seconds,
            )
            return CommandResult(
                stdout=completed.stdout,
                stderr=completed.stderr,
                returncode=completed.returncode,
            )
        except FileNotFoundError:
            return CommandResult(
                stdout="",
                stderr="",
                returncode=127,
                error="Command not found: {0}".format(" ".join(args)),
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                stdout="",
                stderr="",
                returncode=124,
                error="Command timed out: {0}".format(" ".join(args)),
            )
        except OSError as exc:
            return CommandResult(
                stdout="",
                stderr="",
                returncode=1,
                error="Failed to run {0}: {1}".format(" ".join(args), exc),
            )

    def _command_exists(self, command: str) -> bool:
        if Path(command).is_file():
            return True
        return shutil.which(command) is not None

    def _parse_ip_neigh_line(self, line: str) -> Optional[DeviceObservation]:
        tokens = line.split()
        if not tokens:
            return None

        observation = DeviceObservation(source="ip neigh", ip=tokens[0], raw=line)

        for index, token in enumerate(tokens):
            if token == "dev" and index + 1 < len(tokens):
                observation.interface = tokens[index + 1]
            elif token == "lladdr" and index + 1 < len(tokens):
                observation.mac = _normalize_mac(tokens[index + 1])

        last_token = tokens[-1].upper()
        if last_token not in {"DEV", "LLADDR", "ROUTER"}:
            observation.state = last_token

        return observation

    def _parse_arp_line(self, line: str) -> Optional[DeviceObservation]:
        match = ARP_LINE_RE.match(line)
        if not match:
            return None

        hostname = match.group("hostname")
        mac = match.group("mac")
        if mac == "<incomplete>":
            mac = None

        return DeviceObservation(
            source="arp -a",
            ip=match.group("ip"),
            mac=_normalize_mac(mac),
            hostname=None if hostname == "?" else hostname,
            interface=match.group("interface"),
            state="INCOMPLETE" if mac is None else "ARP",
            raw=line,
        )

    def _parse_nmap_output(self, output: str) -> List[DeviceObservation]:
        devices: List[DeviceObservation] = []
        current: Optional[DeviceObservation] = None
        raw_lines: List[str] = []

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            report_match = NMAP_REPORT_RE.match(line)
            if report_match:
                if current:
                    current.raw = "\n".join(raw_lines)
                    devices.append(current)

                target = report_match.group("target")
                hostname, ip = self._split_nmap_target(target)
                current = DeviceObservation(
                    source="nmap -sn",
                    ip=ip,
                    hostname=hostname,
                    state="UP",
                )
                raw_lines = [line]
                continue

            if current is None:
                continue

            raw_lines.append(line)
            mac_match = NMAP_MAC_RE.match(line)
            if mac_match:
                current.mac = _normalize_mac(mac_match.group("mac"))

        if current:
            current.raw = "\n".join(raw_lines)
            devices.append(current)

        return devices

    def _parse_speedport_output(self, output: str) -> List[DeviceObservation]:
        devices: List[DeviceObservation] = []
        lines = [line.rstrip() for line in output.splitlines() if line.strip()]
        header_seen = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("+") and stripped.endswith("+"):
                continue

            if "|" not in stripped:
                continue

            columns = [part.strip() for part in stripped.strip("|").split("|")]
            if len(columns) != 4:
                continue

            if columns[0].lower() == "ipv4":
                header_seen = True
                continue

            if not header_seen:
                continue

            ip_value, name_value, type_value, connected_value = columns
            devices.append(
                DeviceObservation(
                    source="speedport devices",
                    ip=ip_value or None,
                    hostname=_normalize_hostname(name_value) if name_value else None,
                    interface=type_value or None,
                    state=connected_value,
                    raw=line,
                )
            )

        return devices

    def _split_nmap_target(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        if target.endswith(")") and " (" in target:
            hostname, ip = target.rsplit(" (", 1)
            return hostname, ip[:-1]

        if self._looks_like_ip(target):
            return None, target

        return target, None

    def _find_match(self, devices: List[DeviceObservation]) -> Optional[MatchResult]:
        for device in devices:
            match = self._match_device(device)
            if match:
                return match
        return None

    def _match_device(self, device: DeviceObservation) -> Optional[MatchResult]:
        if not device.is_probably_present():
            return None

        if device.mac and device.mac in self.config.target_macs:
            return MatchResult(
                matched_by="mac_address",
                target_identifier=device.mac,
                confidence="high",
                observation=device,
            )

        if device.ip and device.ip in self.config.target_ips:
            if device.source in {"nmap -sn", "speedport devices"}:
                confidence = "high"
            else:
                confidence = "medium"
            return MatchResult(
                matched_by="ip_address",
                target_identifier=device.ip,
                confidence=confidence,
                observation=device,
            )

        for candidate in _hostname_candidates(device.hostname):
            if candidate in self.config.target_hostnames:
                confidence = "medium" if device.source in {"nmap -sn", "speedport devices"} else "low"
                return MatchResult(
                    matched_by="hostname",
                    target_identifier=candidate,
                    confidence=confidence,
                    observation=device,
                )

        return None

    def _maybe_fill_hostnames(self, devices: List[DeviceObservation]) -> None:
        if not self.config.enable_reverse_dns:
            return

        for device in devices:
            if device.hostname or not device.ip:
                continue

            try:
                hostname, _, _ = socket.gethostbyaddr(device.ip)
            except (socket.herror, socket.gaierror, OSError):
                continue

            device.hostname = hostname

    def _looks_like_ip(self, value: str) -> bool:
        try:
            socket.inet_pton(socket.AF_INET, value)
            return True
        except OSError:
            pass

        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except OSError:
            return False
