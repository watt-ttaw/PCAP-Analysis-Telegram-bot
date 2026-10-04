#!/usr/bin/env python3
"""
report.py - turn a PCAP / PCAPNG file into a PDF network forensics (triage) report.

Pipeline:  tshark (extract fields) -> pandas (analyse) -> matplotlib/networkx (charts)
           -> ReportLab (PDF).  Optionally adds an AI-written summary via OpenRouter.

Usage (command line):
    python report.py capture.pcap
    python report.py capture.pcap -o my_report.pdf --ai

Usage (from your bot):
    from report import build_report
    pdf_path = build_report("uploads/abc123.pcap", out_path="uploads/abc123_report.pdf", ai=True)

Requirements:
    pip install pandas matplotlib networkx reportlab requests
    tshark on PATH (installed with Wireshark), or set TSHARK_PATH.

Optional env vars for the AI summary:
    OPENROUTER_API_KEY, OPENROUTER_MODEL (default: openrouter/auto)

Only analyse traffic you own or have permission to analyse.
"""
import argparse
import base64
import hashlib
import io
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import matplotlib

matplotlib.use("Agg")  # no display needed (works on servers)
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (Image, KeepTogether, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

TSHARK_TIMEOUT = 180  # seconds; protects the server from pathological files
DEFAULT_MAX_PACKETS = 200_000

# tshark 4.x names the protocol column "_ws.col.protocol"; tshark 3.x used "_ws.col.Protocol".
PROTO_FIELD_NAMES = ("_ws.col.protocol", "_ws.col.Protocol")

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "frame.len", "dns.qry.name",
    "tls.handshake.extensions_server_name", "http.host",
]


# --------------------------------------------------------------------------
# tshark helpers
# --------------------------------------------------------------------------
def find_tshark():
    env = os.environ.get("TSHARK_PATH")
    if env and os.path.exists(env):
        return env
    found = shutil.which("tshark")
    if found:
        return found
    win = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win):
        return win
    raise FileNotFoundError("tshark not found. Install Wireshark or set TSHARK_PATH.")


def tshark_version(tshark):
    try:
        out = subprocess.run([tshark, "-v"], capture_output=True, text=True, timeout=20).stdout
        return out.splitlines()[0].strip()
    except Exception:
        return "unknown"


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_packets(tshark, pcap, max_packets):
    res = None
    for proto_field in PROTO_FIELD_NAMES:
        cmd = [tshark, "-r", pcap, "-c", str(max_packets), "-T", "fields",
               "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
        for f in FIELDS + [proto_field]:
            cmd += ["-e", f]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ValueError("Analysis timed out - the capture is too large or complex.")
        if res.stdout.strip():
            break
    if not res or not res.stdout.strip():
        raise ValueError("No packets could be read. Is this a valid PCAP/PCAPNG file?")

    df = pd.read_csv(io.StringIO(res.stdout), dtype=str)
    proto_col = next(c for c in df.columns if c.lower() == "_ws.col.protocol")
    df["time"] = pd.to_datetime(pd.to_numeric(df["frame.time_epoch"], errors="coerce"), unit="s")
    df["len"] = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0).astype(int)
    df["src"] = df["ip.src"].fillna(df["ipv6.src"])
    df["dst"] = df["ip.dst"].fillna(df["ipv6.dst"])
    df["sport"] = pd.to_numeric(df["tcp.srcport"].fillna(df["udp.srcport"]), errors="coerce")
    df["dport"] = pd.to_numeric(df["tcp.dstport"].fillna(df["udp.dstport"]), errors="coerce")
    df["proto"] = df[proto_col].fillna("Other")
    df = df.dropna(subset=["time"]).reset_index(drop=True)
    if df.empty:
        raise ValueError("The capture contains no readable packets.")
    return df


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------
def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def timeline_series(df):
    """Bytes per time bucket; bucket size scales with capture length (~120 points)."""
    duration = (df.time.max() - df.time.min()).total_seconds()
    step = max(1, int(duration / 120))
    series = df.set_index("time")["len"].resample(f"{step}s").sum()
    return series, step


def top_conversations(ip_df, n=10):
    lo = ip_df.src.where(ip_df.src <= ip_df.dst, ip_df.dst)
    hi = ip_df.dst.where(ip_df.src <= ip_df.dst, ip_df.src)
    return (ip_df.assign(a=lo, b=hi)
            .groupby(["a", "b"])
            .agg(packets=("len", "size"), bytes=("len", "sum"))
            .sort_values("bytes", ascending=False).head(n).reset_index())


def top_talkers(ip_df, n=8):
    return ip_df.groupby("src")["len"].sum().sort_values(ascending=False).head(n)


def top_names(df, column, n=12):
    return df[column].dropna().str.lower().value_counts().head(n)


def find_indicators(df, ip_df, series, step):
    """Simple rule-based heuristics. They flag things worth a look - not proof."""
    found = []

    # 1. Port scan: one source hitting many distinct destination ports
    ports = ip_df.dropna(subset=["dport"]).groupby("src")["dport"].nunique()
    for ip, n in ports[ports >= 100].sort_values(ascending=False).head(5).items():
        found.append(("Possible port scan", f"{ip} contacted {n} distinct destination ports"))

    # 2. Beaconing: very regular connection intervals
    flows = ip_df.dropna(subset=["dport"]).groupby(["src", "dst", "dport"])
    sizes = flows.size()
    beacons = 0
    for key in sizes[sizes >= 20].index[:300]:
        g = flows.get_group(key)
        gaps = g.time.sort_values().diff().dt.total_seconds().dropna()
        mean = gaps.mean()
        if mean >= 2 and gaps.std() / mean < 0.15:
            src, dst, dport = key
            found.append(("Possible beaconing",
                          f"{src} -> {dst}:{int(dport)} every ~{mean:.0f}s "
                          f"({len(g)} packets, very regular)"))
            beacons += 1
            if beacons >= 5:
                break

    # 3. Unusual DNS names (possible tunnelling / generated domains)
    names = df["dns.qry.name"].dropna().unique()
    odd = [n for n in names if len(n) > 50 or any(len(lbl) > 30 for lbl in n.split("."))]
    for name in odd[:5]:
        found.append(("Unusual DNS name", name))

    # 4. Cleartext protocols
    counts = df["proto"].value_counts()
    for proto in ("FTP", "TELNET", "HTTP", "POP", "IMAP", "SMTP"):
        if proto in counts:
            found.append(("Cleartext protocol", f"{proto}: {counts[proto]} packets (not encrypted)"))

    # 5. Traffic burst
    nz = series[series > 0]
    if len(nz) >= 10 and nz.max() > 10 * nz.median() and nz.max() > 1_000_000:
        found.append(("Traffic burst",
                      f"{human(nz.max())} in one {step}s window at {nz.idxmax():%Y-%m-%d %H:%M:%S} UTC "
                      f"(median window: {human(nz.median())})"))
    return found


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------
def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def chart_timeline(series, step, path):
    fig, ax = plt.subplots(figsize=(7, 3))
    ax.fill_between(series.index, series.values / step / 1024, alpha=0.3)
    ax.plot(series.index, series.values / step / 1024, linewidth=1)
    ax.set_ylabel("KB/s (average)")
    ax.set_title("Traffic over time (UTC)")
    fig.autofmt_xdate()
    return _save(fig, path)


def chart_protocols(df, path):
    counts = df["proto"].value_counts().head(8)
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(counts.index[::-1], counts.values[::-1])
    ax.set_xlabel("Packets")
    ax.set_title("Top protocols")
    return _save(fig, path)


def chart_talkers(talkers, path):
    mb = talkers / 1024 / 1024
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(mb.index[::-1], mb.values[::-1])
    ax.set_xlabel("MB sent")
    ax.set_title("Top talkers (by data sent)")
    return _save(fig, path)


def chart_graph(conv, path):
    if len(conv) < 1:
        return None
    G = nx.Graph()
    for _, r in conv.iterrows():
        G.add_edge(r["a"], r["b"], volume=r["bytes"])  # not "weight": that would distort the layout
    widths = [1 + 5 * G[u][v]["volume"] / conv["bytes"].max() for u, v in G.edges]
    pos = nx.spring_layout(G, seed=1, k=1.5, iterations=200, weight=None)
    fig = plt.figure(figsize=(7, 5))
    nx.draw_networkx_edges(G, pos, width=widths, alpha=0.6)
    nx.draw_networkx_nodes(G, pos, node_size=450, node_color="#9ecae1")
    nx.draw_networkx_labels(G, pos, font_size=7,
                            bbox=dict(facecolor="white", alpha=0.75, edgecolor="none", pad=0.5))
    plt.axis("off")
    plt.title("Conversation graph (line thickness = data volume)")
    return _save(fig, path)


# --------------------------------------------------------------------------
# Optional AI summary (OpenRouter)
# --------------------------------------------------------------------------
def ai_summary(facts):
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        return ""
    prompt = (
        "You are helping a student read a network capture triage report. Using ONLY the "
        "facts below, write a short plain-language summary (max 150 words): what the "
        "traffic looks like, anything worth a closer look, and what to check next. Do "
        "not invent details and say when something is uncertain. No markdown.\n\n" + facts
    )
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={"model": os.environ.get("OPENROUTER_MODEL", "openrouter/auto"),
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=60)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
        return re.sub(r"[*#`]", "", text).strip()
    except Exception:
        return ""  # the report is still useful without it


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------
STYLES = getSampleStyleSheet()
CELL = ParagraphStyle("cell", parent=STYLES["Normal"], fontSize=7.5, leading=9)
CELL_B = ParagraphStyle("cellb", parent=CELL, fontName="Helvetica-Bold")


def P(text, style="Normal"):
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), STYLES[style])


def table(rows, header, widths=None):
    data = [[Paragraph(escape(h), CELL_B) for h in header]]
    data += [[Paragraph(escape(str(c)), CELL) for c in row] for row in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def image(path, width=460):
    w, h = ImageReader(path).getSize()
    return Image(path, width=width, height=width * h / w)


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(2 * cm, 1.2 * cm, "Automated triage report - verify findings before relying on them")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()


def build_report(pcap_path, out_path=None, ai=False, max_packets=DEFAULT_MAX_PACKETS, return_data=False):
    pcap_path = os.path.abspath(pcap_path)
    out_path = out_path or os.path.splitext(pcap_path)[0] + "_report.pdf"
    tshark = find_tshark()

    sha = sha256_of(pcap_path)
    size = os.path.getsize(pcap_path)
    df = load_packets(tshark, pcap_path, max_packets)
    ip_df = df.dropna(subset=["src", "dst"])
    truncated = len(df) >= max_packets

    start, end = df.time.min(), df.time.max()
    duration = (end - start).total_seconds()
    hosts = pd.unique(pd.concat([ip_df.src, ip_df.dst])).size if not ip_df.empty else 0

    series, step = timeline_series(df)
    conv = top_conversations(ip_df) if not ip_df.empty else pd.DataFrame(columns=["a", "b", "packets", "bytes"])
    talkers = top_talkers(ip_df) if not ip_df.empty else pd.Series(dtype=float)
    indicators = find_indicators(df, ip_df, series, step)
    dns_names = top_names(df, "dns.qry.name")
    sni_names = top_names(df, "tls.handshake.extensions_server_name")
    http_hosts = top_names(df, "http.host")

    summary = ""
    if ai:
        facts = (
            f"Packets: {len(df)}, total bytes: {human(df.len.sum())}, duration: {duration:.0f}s, "
            f"hosts: {hosts}\n"
            f"Top protocols: {df['proto'].value_counts().head(6).to_dict()}\n"
            f"Top conversations (a, b, packets, bytes): {conv.head(5).values.tolist()}\n"
            f"Top DNS names: {dns_names.head(8).to_dict()}\n"
            f"Indicators: {indicators if indicators else 'none triggered'}"
        )
        summary = ai_summary(facts)

    workdir = tempfile.mkdtemp(prefix="pcapreport_")  # unique per job: no clashes between users
    try:
        story = [P("Network Forensics Report", "Title"), Spacer(1, 6)]

        info = [
            ("File", os.path.basename(pcap_path)),
            ("Size", human(size)),
            ("SHA-256", sha),
            ("Packets analysed", f"{len(df):,}" + (f" (limit of {max_packets:,} reached - file truncated)" if truncated else "")),
            ("Capture window (UTC)", f"{start:%Y-%m-%d %H:%M:%S} to {end:%Y-%m-%d %H:%M:%S}  ({duration:.0f}s)"),
            ("Total data", human(df.len.sum())),
            ("Unique IP hosts", hosts),
            ("Tool", tshark_version(tshark)),
            ("Report generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")),
        ]
        story += [table(info, ["Item", "Value"], [4 * cm, 13 * cm]), Spacer(1, 12)]

        if summary:
            story += [P("Summary (AI-generated - verify before relying on it)", "Heading2"),
                      P(summary), Spacer(1, 10)]

        story.append(P("Indicators (heuristics, not conclusions)", "Heading2"))
        if indicators:
            story.append(table(indicators, ["Indicator", "Detail"], [4 * cm, 13 * cm]))
        else:
            story.append(P("No indicators were triggered by the built-in rules."))
        story.append(Spacer(1, 12))

        timeline = chart_timeline(series, step, os.path.join(workdir, "timeline.png"))
        story.append(KeepTogether([P("Traffic timeline", "Heading2"), image(timeline)]))

        proto = chart_protocols(df, os.path.join(workdir, "protocols.png"))
        story.append(KeepTogether([P("Protocols", "Heading2"), image(proto, 400)]))

        if len(talkers):
            tk = chart_talkers(talkers, os.path.join(workdir, "talkers.png"))
            story.append(KeepTogether([P("Top talkers", "Heading2"), image(tk, 400)]))

        if len(conv):
            graph = chart_graph(conv, os.path.join(workdir, "graph.png"))
            story.append(KeepTogether([P("Conversation graph", "Heading2"), image(graph, 430)]))
            story.append(P("Top conversations", "Heading2"))
            rows = [(r.a, r.b, f"{r.packets:,}", human(r.bytes)) for r in conv.itertuples()]
            story.append(table(rows, ["Host A", "Host B", "Packets", "Data"], [5.5 * cm, 5.5 * cm, 3 * cm, 3 * cm]))
            story.append(Spacer(1, 10))

        for title, names in (("DNS queries", dns_names), ("TLS server names (SNI)", sni_names),
                             ("HTTP hosts", http_hosts)):
            if len(names):
                story.append(P(title, "Heading2"))
                story.append(table([(n, c) for n, c in names.items()], ["Name", "Count"], [14 * cm, 3 * cm]))
                story.append(Spacer(1, 8))

        story.append(KeepTogether([
            P("Methodology and limitations", "Heading2"),
            P("- Packets were read with tshark and analysed with pandas; charts use matplotlib."),
            P("- Indicators are simple heuristics (distinct-port counts, interval regularity, DNS name "
              "length, cleartext protocols, traffic bursts). Legitimate traffic such as CDNs, games or "
              "keep-alives can trigger them."),
            P("- Encrypted traffic (TLS/HTTPS/QUIC) shows metadata only: addresses, names, sizes and timing."),
            P("- This is an automated triage aid, not a certified forensic examination."),
        ]))

        doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                                topMargin=1.8 * cm, bottomMargin=2 * cm,
                                title="Network Forensics Report", author="PCAP Analysis Bot")
        doc.build(story, onFirstPage=footer, onLaterPages=footer)

        data = None
        if return_data:  # JSON-friendly copy of the analysis for the Mini App and the chat bot
            def b64(name):
                p = os.path.join(workdir, name)
                if not os.path.exists(p):
                    return None
                with open(p, "rb") as fh:
                    return "data:image/png;base64," + base64.b64encode(fh.read()).decode()
            data = {
                "meta": [[k, str(v)] for k, v in info],
                "summary": summary,
                "stats": {"packets": len(df), "bytes": human(df.len.sum()),
                          "duration": f"{duration:.0f}s", "hosts": int(hosts)},
                "indicators": [[str(a), str(b)] for a, b in indicators],
                "conversations": [[r.a, r.b, int(r.packets), human(r.bytes)] for r in conv.itertuples()],
                "names": {"DNS queries": [[n, int(c)] for n, c in dns_names.items()],
                          "TLS server names": [[n, int(c)] for n, c in sni_names.items()],
                          "HTTP hosts": [[n, int(c)] for n, c in http_hosts.items()]},
                "charts": {k: b64(k + ".png") for k in ("timeline", "protocols", "talkers", "graph")},
            }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)  # charts are embedded; delete the temp files
    return (out_path, data) if return_data else out_path


def main():
    ap = argparse.ArgumentParser(description="Generate a PDF forensics report from a PCAP file.")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--output")
    ap.add_argument("--ai", action="store_true", help="add an AI summary (needs OPENROUTER_API_KEY)")
    ap.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS)
    args = ap.parse_args()
    print("Report written to", build_report(args.pcap, args.output, args.ai, args.max_packets))


if __name__ == "__main__":
    main()
