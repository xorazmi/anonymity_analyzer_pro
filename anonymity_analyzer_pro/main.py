"""
Anonymity Analyzer Pro — educational GUI (defensive, local system only).
"""

from __future__ import annotations

import json
import logging
import threading
import traceback
from tkinter import BOTH, END, LEFT, RIGHT, W, X, Y, filedialog, messagebox, ttk
import tkinter as tk
from typing import Any

from analyzers.scan_pipeline import run_full_scan

# --- Theme (dark) ---
BG = "#14161c"
PANEL = "#1c1f28"
FG = "#e6e8ef"
MUTED = "#9aa3b2"
ACCENT = "#3d8bfd"
GOOD = "#3ecf8e"
WARN = "#f5a524"
BAD = "#ff6b6b"


class TkLogHandler(logging.Handler):
    """Append log records to a Tk Text widget (thread-safe via root.after)."""

    def __init__(self, root: tk.Tk, widget: tk.Text) -> None:
        super().__init__()
        self.root = root
        self.widget = widget

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)

        def append() -> None:
            try:
                self.widget.configure(state="normal")
                self.widget.insert(END, msg + "\n")
                self.widget.see(END)
                self.widget.configure(state="disabled")
            except tk.TclError:
                pass

        try:
            self.root.after(0, append)
        except tk.TclError:
            pass


class AnonymityAnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Anonymity Analyzer Pro")
        root.geometry("1180x820")
        root.minsize(960, 680)
        root.configure(bg=BG)

        self._last_report: dict[str, Any] | None = None
        self._scan_lock = threading.Lock()

        self._build_ui()
        self._setup_logging()

    def _setup_logging(self) -> None:
        h = TkLogHandler(self.root, self.log_text)
        h.setLevel(logging.INFO)
        h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S"))
        logging.getLogger().addHandler(h)
        logging.getLogger().setLevel(logging.INFO)
        # Quiet third-party noise
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 12))
        style.configure("Hero.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI Semibold", 28))
        style.configure("SubHero.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 11))
        style.configure("TLabelframe", background=PANEL, foreground=FG)
        style.configure("TLabelframe.Label", background=PANEL, foreground=ACCENT, font=("Segoe UI Semibold", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI Semibold", 10))
        style.map("TButton", background=[("active", "#2a3142")])

        outer = ttk.Frame(self.root, style="TFrame")
        outer.pack(fill=BOTH, expand=True)

        header = ttk.Frame(outer, style="TFrame")
        header.pack(fill=X, padx=16, pady=(16, 8))

        ttk.Label(header, text="Anonymity Analyzer Pro", style="Title.TLabel").pack(anchor=W)
        ttk.Label(
            header,
            text="Educational tool: analyzes this device only. 100% anonymity does not exist.",
            style="SubHero.TLabel",
        ).pack(anchor=W)

        hero = tk.Frame(outer, bg=BG)
        hero.pack(fill=X, padx=16, pady=8)
        self.hero_score = tk.Label(
            hero,
            text="Your Anonymity Level: —",
            bg=BG,
            fg=ACCENT,
            font=("Segoe UI Semibold", 28),
        )
        self.hero_score.pack(anchor=W)
        self.hero_level = tk.Label(
            hero,
            text="Level: —",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 11),
        )
        self.hero_level.pack(anchor=W, pady=(4, 0))

        bar_row = ttk.Frame(outer, style="TFrame")
        bar_row.pack(fill=X, padx=16, pady=(4, 8))
        ttk.Label(bar_row, text="Score", style="SubHero.TLabel").pack(anchor=W)
        self.score_bar = ttk.Progressbar(bar_row, maximum=100, length=520, mode="determinate")
        self.score_bar.pack(anchor=W, pady=(0, 6))
        ttk.Label(bar_row, text="Fingerprint uniqueness (est.)", style="SubHero.TLabel").pack(anchor=W)
        self.fp_bar = ttk.Progressbar(bar_row, maximum=100, length=520, mode="determinate")
        self.fp_bar.pack(anchor=W, pady=(0, 6))
        ttk.Label(bar_row, text="Exposure / leak topics (conceptual)", style="SubHero.TLabel").pack(anchor=W)
        self.leak_bar = ttk.Progressbar(bar_row, maximum=100, length=520, mode="determinate")
        self.leak_bar.pack(anchor=W)

        warn_frame = ttk.LabelFrame(outer, text="You are NOT fully anonymous because:", padding=10)
        warn_frame.pack(fill=X, padx=16, pady=8)
        self.warn_text = tk.Text(
            warn_frame,
            height=9,
            wrap="word",
            bg=PANEL,
            fg=WARN,
            insertbackground=FG,
            relief="flat",
            highlightthickness=0,
            font=("Segoe UI", 10),
        )
        self.warn_text.pack(fill=BOTH, expand=True)
        self.warn_text.insert(END, "Run a scan to populate this educational summary.\n")
        self.warn_text.configure(state="disabled")

        btn_row = ttk.Frame(outer, style="TFrame")
        btn_row.pack(fill=X, padx=16, pady=(0, 8))
        self.btn_scan = ttk.Button(btn_row, text="Refresh / Re-scan", command=self.start_scan, style="Accent.TButton")
        self.btn_scan.pack(side=LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Export JSON…", command=lambda: self.export_report("json")).pack(side=LEFT, padx=4)
        ttk.Button(btn_row, text="Export TXT…", command=lambda: self.export_report("txt")).pack(side=LEFT, padx=4)

        body = ttk.Frame(outer, style="TFrame")
        body.pack(fill=BOTH, expand=True, padx=16, pady=(0, 8))

        paned = ttk.Panedwindow(body, orient=tk.HORIZONTAL)
        paned.pack(fill=BOTH, expand=True)

        left = ttk.Frame(paned, style="TFrame")
        right = ttk.Frame(paned, style="TFrame")
        paned.add(left)
        paned.add(right)

        self._section_ip = self._make_section(left, "IP Info")
        self._section_sys = self._make_section(left, "System Info")
        self._section_net = self._make_section(left, "Network Info")

        self._section_leak = self._make_section(right, "Leak detection & Tor/VPN")
        self._section_exp = self._make_section(right, "Explanation engine")
        self._section_time = self._make_section(right, "Detection timeline")

        self.txt_ip = self._scroll_text(self._section_ip)
        self.txt_sys = self._scroll_text(self._section_sys)
        self.txt_net = self._scroll_text(self._section_net)
        self.txt_leak = self._scroll_text(self._section_leak)
        self.txt_exp = self._scroll_text(self._section_exp)
        self.txt_time = self._scroll_text(self._section_time, height=10)

        log_frame = ttk.LabelFrame(outer, text="Activity log", padding=6)
        log_frame.pack(fill=BOTH, expand=False, padx=16, pady=(0, 16))
        self.log_text = tk.Text(
            log_frame,
            height=7,
            wrap="word",
            bg="#0f1117",
            fg=MUTED,
            relief="flat",
            highlightthickness=0,
            font=("Consolas", 9),
            state="disabled",
        )
        self.log_text.pack(fill=BOTH, expand=True)

        self.root.after(200, self.start_scan)

    def _make_section(self, parent: ttk.Frame, title: str) -> ttk.LabelFrame:
        f = ttk.LabelFrame(parent, text=title, padding=8)
        f.pack(fill=BOTH, expand=True, pady=(0, 10))
        return f

    def _scroll_text(self, parent: ttk.LabelFrame, height: int = 9) -> tk.Text:
        fr = ttk.Frame(parent, style="Card.TFrame")
        fr.pack(fill=BOTH, expand=True)
        t = tk.Text(
            fr,
            height=height,
            wrap="word",
            bg=PANEL,
            fg=FG,
            relief="flat",
            highlightthickness=0,
            font=("Segoe UI", 10),
        )
        sb = ttk.Scrollbar(fr, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side=LEFT, fill=BOTH, expand=True)
        sb.pack(side=RIGHT, fill=Y)
        return t

    def _set_text(self, w: tk.Text, content: str) -> None:
        w.configure(state="normal")
        w.delete("1.0", END)
        w.insert("1.0", content)
        w.configure(state="disabled")

    def start_scan(self) -> None:
        if not self._scan_lock.acquire(blocking=False):
            messagebox.showinfo("Busy", "A scan is already running.")
            return

        self.btn_scan.configure(state="disabled")
        self._set_text(self.txt_time, "")
        logging.info("Starting new scan…")

        def worker() -> None:
            err: str | None = None
            bundle: dict[str, Any] = {}

            try:
                bundle = run_full_scan(timeout=12.0)
            except Exception as e:
                err = f"{e}\n{traceback.format_exc()}"
                logging.error("Scan failed: %s", e)
            finally:

                def finish() -> None:
                    self._scan_lock.release()
                    self.btn_scan.configure(state="normal")
                    if err:
                        messagebox.showerror("Scan error", err[:1200])
                        return
                    self._last_report = bundle
                    self._render_bundle(bundle)
                    logging.info("Scan finished.")

                self.root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _render_bundle(self, b: dict[str, Any]) -> None:
        ipr = b.get("ip") or {}
        geo = ipr.get("geo") or {}
        tor = (b.get("tor_vpn") or {}).get("tor") or {}
        sysd = b.get("system") or {}
        net = b.get("network") or {}
        leaks = b.get("leaks") or {}
        score = b.get("score") or {}
        fp = b.get("fingerprint") or {}
        exps = b.get("explanations") or []
        warns = b.get("warnings") or []
        timeline = list(b.get("timeline") or [])
        meta = b.get("scan_meta") or {}
        times = meta.get("timings_ms") or {}
        if times:
            timeline.append("")
            timeline.append("── Timings (wall clock, approximate) ──")
            for k in sorted(times.keys()):
                timeline.append(f"  {k}: {times[k]} ms")

        s_val = int(score.get("score") or 0)
        lvl = score.get("level") or "—"
        ceiling = score.get("display_ceiling", 82)
        self.hero_score.configure(text=f"Your Anonymity Level: {s_val}%")
        self.hero_level.configure(
            text=f"Level: {lvl}  ·  Display cap {ceiling}% (absolute 100% is impossible)  ·  model {score.get('model_version', '')}"
        )

        self.score_bar["value"] = s_val
        u = int(fp.get("uniqueness_score") or 0)
        self.fp_bar["value"] = u
        leak_topics = len(leaks.get("issue_codes") or [])
        self.leak_bar["value"] = min(100, 18 + leak_topics * 16)

        # Color hero by level
        if s_val < 35:
            self.hero_score.configure(fg=BAD)
        elif s_val < 70:
            self.hero_score.configure(fg=WARN)
        else:
            self.hero_score.configure(fg=GOOD)

        ip_lines = []
        if ipr.get("public_ip"):
            ip_lines.append(f"Public IP: {ipr['public_ip']}")
        else:
            ip_lines.append("Public IP: (unavailable)")
        if ipr.get("geo_source"):
            ip_lines.append(f"Geo provider: {ipr['geo_source']}")
        if geo:
            ip_lines.append(f"Country: {geo.get('country', '—')} ({geo.get('countryCode', '')})")
            ip_lines.append(f"Region / City: {geo.get('regionName', '—')} / {geo.get('city', '—')}")
            ip_lines.append(f"ISP: {geo.get('isp', '—')}")
            ip_lines.append(f"Org: {geo.get('org', '—')}")
            ip_lines.append(f"AS: {geo.get('as', '—')}")
        if ipr.get("error") and not geo:
            ip_lines.append(f"Note: {ipr['error']}")
        vpn_like = bool(ipr.get("vpn_likely"))
        ip_lines.append(f"VPN / proxy / hosting (heuristic): {'Likely signals' if vpn_like else 'Not strongly indicated'}")
        for r in ipr.get("vpn_reasons") or []:
            ip_lines.append(f"  • {r}")
        self._set_text(self.txt_ip, "\n".join(ip_lines))

        hh = (sysd.get("hardware_hints") or {})
        sys_lines = [
            f"OS: {sysd.get('os', '—')} {sysd.get('os_release', '')}",
            f"Version string: {sysd.get('os_version', '—')[:120]}…" if len(str(sysd.get('os_version', ''))) > 120 else f"Version string: {sysd.get('os_version', '—')}",
            f"Platform: {sysd.get('platform_pretty', '—')}",
            f"CPU arch (process): {sysd.get('architecture', '—')}",
            f"Hostname: {sysd.get('hostname', '—')}",
            f"Username: {sysd.get('username', '—')}",
            f"Machine / CPU (OS-reported): {hh.get('machine', '—')} / {hh.get('processor', '—')}",
        ]
        if hh.get("uuid_node_hex"):
            sys_lines.append(f"UUID node (educational): {hh['uuid_node_hex']}")
            sys_lines.append(f"  → {hh.get('uuid_node_note', '')}")
        sys_lines.append("")
        sys_lines.append(f"Default locale: {sysd.get('default_locale', '—')} ({sysd.get('preferred_encoding', '—')})")
        sys_lines.append(f"Timezone: {sysd.get('timezone_label', '—')} (offset min: {sysd.get('timezone_offset_minutes', '—')})")
        sys_lines.append(f"Fingerprint uniqueness (rough): {fp.get('uniqueness_score', '—')}/100")
        sys_lines.append(fp.get("note", ""))
        self._set_text(self.txt_sys, "\n".join(sys_lines))

        net_lines = [f"Estimated local IPv4 (route guess): {net.get('local_ip', '—')}"]
        net_lines.append(f"Non-loopback IPv4 interfaces (psutil): {net.get('ipv4_non_loopback_interface_count', '—')}")
        dns = net.get("dns_servers") or []
        net_lines.append("DNS servers (best effort):" + (" none listed" if not dns else ""))
        for d in dns:
            net_lines.append(f"  • {d}")
        if not net.get("psutil_available"):
            net_lines.append("Install psutil for richer interface listing (pip install psutil).")
        for iface in net.get("interfaces") or []:
            bits = [iface.get("name")]
            if iface.get("ipv4"):
                bits.append(f"IPv4 {iface['ipv4']}")
            if iface.get("ipv6"):
                bits.append(f"IPv6 {iface['ipv6']}")
            if iface.get("is_up") is not None:
                bits.append("up" if iface["is_up"] else "down")
            net_lines.append("  • " + " | ".join(str(x) for x in bits if x))
        self._set_text(self.txt_net, "\n".join(net_lines))

        tv = b.get("tor_vpn") or {}
        leak_lines = []
        leak_lines.append("=== Tor (Tor Project API, this connection) ===")
        if tor.get("checked"):
            leak_lines.append(f"IsTor: {tor.get('is_tor')}")
            leak_lines.append(f"Reported IP (Tor check): {tor.get('reported_ip', '—')}")
            if tor.get("note"):
                leak_lines.append(f"Note: {tor['note']}")
        else:
            leak_lines.append(f"Tor check unavailable: {tor.get('error', 'unknown')}")
            if tor.get("hint"):
                leak_lines.append(f"Tip: {tor['hint']}")
        leak_lines.append("")
        leak_lines.append("=== Conceptual leak topics ===")
        for n in leaks.get("notes") or []:
            leak_lines.append(f"• {n}")
        leak_lines.append("Issue flags: " + ", ".join(leaks.get("issue_codes") or []) + "\n")
        self._set_text(self.txt_leak, "\n".join(leak_lines))

        exp_lines = []
        for i, ex in enumerate(exps, 1):
            exp_lines.append(f"--- {i}. {ex.get('title', 'Topic')} ---")
            exp_lines.append(f"What: {ex.get('what', '')}")
            exp_lines.append(f"Why anonymity drops: {ex.get('why', '')}")
            exp_lines.append(f"Real world: {ex.get('real_world', '')}\n")
        self._set_text(self.txt_exp, "\n".join(exp_lines) if exp_lines else "(No explanations — run scan.)")

        self.warn_text.configure(state="normal")
        self.warn_text.delete("1.0", END)
        for w in warns:
            self.warn_text.insert(END, f"• {w}\n")
        self.warn_text.configure(state="disabled")

        self._set_text(self.txt_time, "\n".join(timeline))

    def export_report(self, mode: str) -> None:
        if not self._last_report:
            messagebox.showwarning("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json" if mode == "json" else ".txt",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            if mode == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._last_report, f, indent=2, ensure_ascii=False)
            else:
                lines = self._human_report(self._last_report)
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            messagebox.showinfo("Exported", path)
            logging.info("Report exported to %s", path)
        except OSError as e:
            messagebox.showerror("Export failed", str(e))

    def _human_report(self, b: dict[str, Any]) -> list[str]:
        lines = ["ANONYMITY ANALYZER PRO — EDUCATIONAL REPORT", "=" * 50, ""]
        sc = b.get("score") or {}
        lines.append(f"Anonymity score: {sc.get('score')}%  Level: {sc.get('level')}")
        lines.append(f"Display ceiling: {sc.get('display_ceiling', '—')}%  (literal 100% is not representable)")
        lines.append(f"Model: {sc.get('model_version', '—')}")
        lines.append("")
        lines.extend("• " + w for w in (b.get("warnings") or []))
        lines.append("")
        sm = (b.get("scan_meta") or {}).get("timings_ms") or {}
        if sm:
            lines.append("TIMINGS (MS)")
            for k in sorted(sm.keys()):
                lines.append(f"  {k}: {sm[k]}")
            lines.append("")
        lines.append("TIMELINE")
        lines.extend(b.get("timeline") or [])
        return lines


def main() -> None:
    root = tk.Tk()
    # Default font scaling on HiDPI Windows
    try:
        root.tk.call("tk", "scaling", float(root.tk.call("tk", "scaling")))
    except tk.TclError:
        pass
    AnonymityAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
