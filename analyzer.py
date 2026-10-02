import os
import shutil
import subprocess
from collections import Counter

TIMEOUT = 60  # seconds per tshark call


def find_tshark() -> str:
    """Find tshark on PATH, or in the default Windows install folders."""
    found = shutil.which("tshark")
    if found:
        return found
    for p in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ):
        if os.path.exists(p):
            return p
    return "tshark"


TSHARK = find_tshark()

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # pcap little-endian
    b"\xa1\xb2\xc3\xd4",  # pcap big-endian
    b"\x4d\x3c\xb2\xa1",  # pcap nanosecond LE
    b"\xa1\xb2\x3c\x4d",  # pcap nanosecond BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


def is_pcap(path: str) -> bool:
    """Check file magic bytes so we only process real capture files."""
    with open(path, "rb") as f:
        return f.read(4) in PCAP_MAGICS


def run_tshark(args: list[str]) -> str:
    """Run tshark safely: no shell, with a timeout."""
    result = subprocess.run(
        [TSHARK, "-n", *args],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )
    return result.stdout


def fields(path: str, display_filter: str, *field_names: str) -> list[list[str]]:
    """Return rows of the requested fields for packets matching a filter."""
    args = ["-r", path, "-Y", display_filter, "-T", "fields"]
    for name in field_names:
        args += ["-e", name]
    out = run_tshark(args)
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def summary(path: str) -> dict:
    report = {}

    # Basic counts
    all_rows = fields(path, "frame", "frame.time_epoch", "frame.len")
    report["packets"] = len(all_rows)
    times = [float(r[0]) for r in all_rows if r and r[0]]
    report["duration_s"] = round(max(times) - min(times), 2) if times else 0
    report["bytes"] = sum(int(r[1]) for r in all_rows if len(r) > 1 and r[1])

    # Protocol hierarchy and top conversations (raw text, trimmed)
    phs = run_tshark(["-r", path, "-q", "-z", "io,phs"])
    report["protocols"] = "\n".join(phs.splitlines()[:20])

    conv = run_tshark(["-r", path, "-q", "-z", "conv,ip"])
    report["conversations"] = "\n".join(conv.splitlines()[:15])

    # DNS
    dns = fields(path, "dns.flags.response == 0", "dns.qry.name")
    report["top_dns"] = Counter(r[0] for r in dns if r and r[0]).most_common(10)

    failed = fields(path, "dns.flags.rcode != 0", "dns.qry.name")
    report["failed_dns"] = Counter(r[0] for r in failed if r and r[0]).most_common(5)

    # HTTP requests
    report["http_requests"] = fields(
        path, "http.request", "ip.src", "http.host", "http.request.uri"
    )[:10]

    # TLS server names (SNI)
    tls = fields(
        path, "tls.handshake.type == 1", "tls.handshake.extensions_server_name"
    )
    report["top_tls"] = Counter(r[0] for r in tls if r and r[0]).most_common(10)

    # Possible port scan: sources hitting many distinct destination ip:port pairs
    syn = fields(
        path, "tcp.flags.syn==1 && tcp.flags.ack==0",
        "ip.src", "ip.dst", "tcp.dstport",
    )
    targets_by_src = {}
    for row in syn:
        if len(row) == 3:
            targets_by_src.setdefault(row[0], set()).add((row[1], row[2]))
    report["scan_suspects"] = [
        (src, len(t)) for src, t in targets_by_src.items() if len(t) >= 50
    ]

    # Executable / script downloads over HTTP
    report["exe_downloads"] = fields(
        path,
        'http.request.uri matches "(?i)\\\\.(exe|dll|ps1|js|vbs|bat|scr)$"',
        "http.host", "http.request.uri",
    )[:10]

    return report


def format_report(r: dict) -> str:
    lines = ["PCAP ANALYSIS REPORT", "=" * 22]
    lines.append(f"Packets: {r.get('packets', 0)}")
    lines.append(f"Duration: {r.get('duration_s', 0)} s")
    lines.append(f"Total bytes: {r.get('bytes', 0)}")

    lines.append("\nTop DNS queries:")
    lines += [f"  {n}  x{c}" for n, c in r["top_dns"]] or ["  none"]

    if r["failed_dns"]:
        lines.append("\nFailed DNS lookups:")
        lines += [f"  {n}  x{c}" for n, c in r["failed_dns"]]

    lines.append("\nTop TLS server names:")
    lines += [f"  {n}  x{c}" for n, c in r["top_tls"]] or ["  none"]

    lines.append("\nHTTP requests (first 10):")
    if r["http_requests"]:
        for row in r["http_requests"]:
            lines.append("  " + " | ".join(row))
    else:
        lines.append("  none")

    flags = []
    if r["scan_suspects"]:
        flags.append(
            "Possible port scan from: "
            + ", ".join(f"{s} ({n} targets)" for s, n in r["scan_suspects"])
        )
    if r["exe_downloads"]:
        flags.append(
            "Executable/script downloads over HTTP: "
            + "; ".join("".join(x) for x in r["exe_downloads"])
        )
    lines.append("\nFlags:")
    lines += [f"  - {f}" for f in flags] or ["  - nothing obvious flagged"]

    lines.append("\nProtocol hierarchy:")
    lines.append(r["protocols"] or "  (none)")

    lines.append("\nTop IP conversations:")
    lines.append(r["conversations"] or "  (none)")

    lines.append("\nNote: automated checks only. Verify findings manually.")
    return "\n".join(lines)
