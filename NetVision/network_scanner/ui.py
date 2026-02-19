import customtkinter as ctk
import threading
import collections
import os
import sys
import tkinter as tk
from scanner import (
    NetworkScanner, PacketSniffer,
    PortScanner, SpeedTester, NetworkInfo, parse_ports_spec,
)

# ── Theme ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_HEADER = ("Segoe UI", 13, "bold")
FONT_BODY   = ("Segoe UI", 12)
FONT_MONO   = ("Consolas", 11)
FONT_BIG    = ("Segoe UI", 36, "bold")
FONT_MED    = ("Segoe UI", 16)

MAX_PACKET_LINES  = 500
BATCH_INTERVAL_MS = 100

# Accent colours
CLR_BLUE   = "#4fc3f7"
CLR_GREEN  = "#66bb6a"
CLR_YELLOW = "#fdd835"
CLR_RED    = "#ef5350"
CLR_PURPLE = "#ab47bc"
CLR_GREY   = "#bdbdbd"


class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self._icon_photo = None
        self._set_app_icon()

        self.title("NetVision  —  Network Toolkit")
        self.geometry("1020x680")
        self.minsize(860, 540)

        # Backend helpers
        self.scanner      = NetworkScanner()
        self.sniffer      = PacketSniffer()
        self.port_scanner = PortScanner()
        self.speed_tester = SpeedTester()
        self.net_info     = NetworkInfo()

        # State
        self.scanning    = False
        self._pkt_queue  = collections.deque()
        self._pkt_total  = 0
        self._port_scanning = False

        # ── Root grid ────────────────────────────────────────────────
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        # ── Header ──────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(14, 2), sticky="ew")

        ctk.CTkLabel(
            header, text="NetVision", font=FONT_TITLE, text_color=CLR_BLUE,
        ).pack(side="left")

        self.status_label = ctk.CTkLabel(
            header, text="Ready", font=FONT_BODY, text_color="gray",
        )
        self.status_label.pack(side="right", padx=12)

        # ── Tabs ────────────────────────────────────────────────────
        self.tabs = ctk.CTkTabview(self, anchor="nw")
        self.tabs.grid(row=1, column=0, padx=20, pady=(2, 14), sticky="nsew")

        self.tab_devices  = self.tabs.add("  Devices  ")
        self.tab_packets  = self.tabs.add("  Packets  ")
        self.tab_ports    = self.tabs.add("  Ports  ")
        self.tab_speed    = self.tabs.add("  Speed  ")
        self.tab_info     = self.tabs.add("  Info  ")

        self._build_devices_tab()
        self._build_packets_tab()
        self._build_ports_tab()
        self._build_speed_tab()
        self._build_info_tab()

        # Packet flush loop
        self._flush_packets()

    @staticmethod
    def _asset_path(*parts):
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, *parts)

    def _set_app_icon(self):
        icon_ico = self._asset_path("assets", "netvision_logo.ico")
        icon_png = self._asset_path("assets", "netvision_logo.png")

        # Prefer .ico on Windows for taskbar/titlebar consistency.
        if os.path.exists(icon_ico):
            try:
                self.iconbitmap(icon_ico)
            except Exception:
                pass

        # Fallback for environments where iconbitmap is unavailable.
        if os.path.exists(icon_png):
            try:
                self._icon_photo = tk.PhotoImage(file=icon_png)
                self.iconphoto(True, self._icon_photo)
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════
    #  1 ▸ DEVICES
    # ═══════════════════════════════════════════════════════════════
    def _build_devices_tab(self):
        self.tab_devices.grid_columnconfigure(0, weight=1)
        self.tab_devices.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(self.tab_devices, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")

        self.scan_btn = ctk.CTkButton(bar, text="Scan Network", width=160,
                                      command=self._start_device_scan)
        self.scan_btn.pack(side="left")

        self.dev_count = ctk.CTkLabel(bar, text="", font=FONT_BODY,
                                      text_color="gray")
        self.dev_count.pack(side="right", padx=8)

        self.dev_frame = ctk.CTkScrollableFrame(self.tab_devices,
                                                label_text="Connected Devices")
        self.dev_frame.grid(row=1, column=0, sticky="nsew")
        for c, w in enumerate([1, 1, 2]):
            self.dev_frame.grid_columnconfigure(c, weight=w)
        self._dev_headers()

    def _dev_headers(self):
        for w in self.dev_frame.winfo_children():
            w.destroy()
        for c, t in enumerate(["IP Address", "MAC Address", "Vendor"]):
            ctk.CTkLabel(self.dev_frame, text=t, font=FONT_HEADER
                         ).grid(row=0, column=c, padx=6, pady=4, sticky="w")

    def _start_device_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning…")
        self.status_label.configure(text="Scanning devices…", text_color=CLR_YELLOW)
        self._dev_headers()
        threading.Thread(target=self._dev_worker, daemon=True).start()

    def _dev_worker(self):
        devs = self.scanner.scan()
        self.after(0, self._dev_populate, devs)

    def _dev_populate(self, devs):
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Scan Network")
        self.status_label.configure(text=f"Found {len(devs)} device(s)",
                                    text_color=CLR_GREEN)
        self.dev_count.configure(text=f"{len(devs)} device(s)")
        for i, d in enumerate(devs, 1):
            for c, k in enumerate(["ip", "mac", "vendor"]):
                ctk.CTkLabel(self.dev_frame, text=d[k], font=FONT_BODY
                             ).grid(row=i, column=c, padx=6, pady=2, sticky="w")

    # ═══════════════════════════════════════════════════════════════
    #  2 ▸ PACKETS
    # ═══════════════════════════════════════════════════════════════
    def _build_packets_tab(self):
        self.tab_packets.grid_columnconfigure(0, weight=1)
        self.tab_packets.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(self.tab_packets, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")

        self.sniff_btn = ctk.CTkButton(bar, text="Start Capture", width=160,
                                       command=self._toggle_sniff)
        self.sniff_btn.pack(side="left")

        ctk.CTkButton(bar, text="Clear", width=80, fg_color="#424242",
                       hover_color="#616161", command=self._clear_pkts
                       ).pack(side="left", padx=8)

        self.autoscroll_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(bar, text="Auto-scroll", variable=self.autoscroll_var,
                        font=FONT_BODY, width=20).pack(side="left", padx=12)

        self.pkt_count = ctk.CTkLabel(bar, text="0 packets", font=FONT_BODY,
                                      text_color="gray")
        self.pkt_count.pack(side="right", padx=8)

        hdr = f"{'Time':<10} {'Source':<18} {'Destination':<18} {'Proto':<7} {'Len':<6} Info"
        ctk.CTkLabel(self.tab_packets, text=hdr, font=FONT_MONO, anchor="w",
                     text_color=CLR_BLUE).grid(row=1, column=0, padx=6, sticky="ew")

        self.pkt_box = ctk.CTkTextbox(self.tab_packets, font=FONT_MONO,
                                      wrap="none", state="disabled",
                                      activate_scrollbars=True)
        self.pkt_box.grid(row=2, column=0, sticky="nsew")

    def _toggle_sniff(self):
        if self.sniffer.is_sniffing:
            self.sniffer.stop()
            self.sniff_btn.configure(text="Start Capture", fg_color="#1f6aa5")
            self.status_label.configure(text="Capture stopped", text_color="gray")
        else:
            self.sniffer.start(callback=lambda p: self._pkt_queue.append(p))
            self.sniff_btn.configure(text="Stop Capture", fg_color="#c62828")
            self.status_label.configure(text="Capturing…", text_color=CLR_BLUE)

    def _flush_packets(self):
        batch = []
        try:
            while self._pkt_queue:
                batch.append(self._pkt_queue.popleft())
        except IndexError:
            pass
        if batch:
            self._pkt_total += len(batch)
            lines = []
            for p in batch:
                lines.append(
                    f"{p['time']:<10} {p['src']:<18} {p['dst']:<18} "
                    f"{p['protocol']:<7} {str(p['length']):<6} {p['info'][:72]}"
                )
            self.pkt_box.configure(state="normal")
            self.pkt_box.insert("end", "\n".join(lines) + "\n")
            cur = int(self.pkt_box.index("end-1c").split(".")[0])
            if cur > MAX_PACKET_LINES:
                self.pkt_box.delete("1.0", f"{cur - MAX_PACKET_LINES + 1}.0")
            self.pkt_box.configure(state="disabled")
            if self.autoscroll_var.get():
                self.pkt_box.see("end")
            self.pkt_count.configure(text=f"{self._pkt_total} packets")
        self.after(BATCH_INTERVAL_MS, self._flush_packets)

    def _clear_pkts(self):
        self._pkt_total = 0
        self.pkt_box.configure(state="normal")
        self.pkt_box.delete("1.0", "end")
        self.pkt_box.configure(state="disabled")
        self.pkt_count.configure(text="0 packets")

    # ═══════════════════════════════════════════════════════════════
    #  3 ▸ PORT SCANNER
    # ═══════════════════════════════════════════════════════════════
    def _build_ports_tab(self):
        self.tab_ports.grid_columnconfigure(0, weight=1)
        self.tab_ports.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(self.tab_ports, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")

        ctk.CTkLabel(bar, text="Target IP:", font=FONT_BODY).pack(side="left")
        self.port_target = ctk.CTkEntry(bar, width=200,
                                        placeholder_text="e.g. 192.168.1.1")
        self.port_target.pack(side="left", padx=6)

        ctk.CTkLabel(bar, text="Ports:", font=FONT_BODY).pack(side="left", padx=(10, 0))
        self.port_spec = ctk.CTkEntry(
            bar,
            width=250,
            placeholder_text="default or 22,80,443,8000-8100",
        )
        self.port_spec.pack(side="left", padx=6)

        self.port_btn = ctk.CTkButton(bar, text="Scan Ports", width=140,
                                      command=self._start_port_scan)
        self.port_btn.pack(side="left", padx=6)

        self.port_status = ctk.CTkLabel(bar, text="", font=FONT_BODY,
                                        text_color="gray")
        self.port_status.pack(side="right", padx=8)

        hdr = f"{'Port':<8} {'Service':<16} {'State'}"
        ctk.CTkLabel(self.tab_ports, text=hdr, font=FONT_MONO, anchor="w",
                     text_color=CLR_BLUE).grid(row=1, column=0, padx=6, sticky="ew")

        self.port_box = ctk.CTkTextbox(self.tab_ports, font=FONT_MONO,
                                       wrap="none", state="disabled",
                                       activate_scrollbars=True)
        self.port_box.grid(row=2, column=0, sticky="nsew")

    def _start_port_scan(self):
        if self._port_scanning:
            return
        target = self.port_target.get().strip()
        if not target:
            self.port_status.configure(text="Enter a target IP", text_color=CLR_RED)
            return
        try:
            ports = parse_ports_spec(self.port_spec.get().strip())
        except ValueError as exc:
            self.port_status.configure(text=str(exc), text_color=CLR_RED)
            return
        self._port_scanning = True
        self.port_btn.configure(state="disabled", text="Scanning…")
        self.port_box.configure(state="normal")
        self.port_box.delete("1.0", "end")
        self.port_box.configure(state="disabled")
        self.status_label.configure(text=f"Scanning {len(ports)} ports on {target}…",
                                    text_color=CLR_YELLOW)
        self.port_status.configure(text="0 open", text_color="gray")
        threading.Thread(target=self._port_worker, args=(target, ports),
                         daemon=True).start()

    def _port_worker(self, target, ports):
        open_count = [0]

        def on_port(port, service, state):
            if state == "open":
                open_count[0] += 1
                line = f"{port:<8} {service:<16} OPEN\n"
                self.after(0, self._port_append, line, open_count[0])

        self.port_scanner.scan(target, ports=ports, callback=on_port)
        self.after(0, self._port_done, open_count[0], len(ports))

    def _port_append(self, line, count):
        self.port_box.configure(state="normal")
        self.port_box.insert("end", line)
        self.port_box.configure(state="disabled")
        self.port_box.see("end")
        self.port_status.configure(text=f"{count} open")

    def _port_done(self, total, scanned):
        self._port_scanning = False
        self.port_btn.configure(state="normal", text="Scan Ports")
        self.status_label.configure(text=f"Port scan done - {total} open of {scanned}",
                                    text_color=CLR_GREEN)
        self.port_status.configure(text=f"{total} open ports", text_color=CLR_GREEN)

    # ═══════════════════════════════════════════════════════════════
    #  4 ▸ SPEED TEST
    # ═══════════════════════════════════════════════════════════════
    def _build_speed_tab(self):
        self.tab_speed.grid_columnconfigure(0, weight=1)
        self.tab_speed.grid_columnconfigure(1, weight=1)
        self.tab_speed.grid_columnconfigure(2, weight=1)
        self.tab_speed.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(self.tab_speed, fg_color="transparent")
        bar.grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky="ew")

        self.speed_btn = ctk.CTkButton(bar, text="Run Speed Test", width=180,
                                       command=self._start_speed)
        self.speed_btn.pack(side="left")

        self.speed_status = ctk.CTkLabel(bar, text="", font=FONT_BODY,
                                         text_color="gray")
        self.speed_status.pack(side="right", padx=8)

        # ── Card: Download ──────────────────────────────────────────
        dl_card = ctk.CTkFrame(self.tab_speed, corner_radius=14)
        dl_card.grid(row=1, column=0, padx=(0, 6), sticky="nsew")
        dl_card.grid_columnconfigure(0, weight=1)
        dl_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(dl_card, text="↓  Download", font=FONT_MED,
                     text_color=CLR_BLUE).grid(row=0, column=0, pady=(24, 0))
        self.dl_val = ctk.CTkLabel(dl_card, text="—", font=FONT_BIG)
        self.dl_val.grid(row=1, column=0, pady=2)
        ctk.CTkLabel(dl_card, text="Mbps", font=FONT_MED,
                     text_color="gray").grid(row=2, column=0, pady=(0, 24))

        # ── Card: Upload ────────────────────────────────────────────
        ul_card = ctk.CTkFrame(self.tab_speed, corner_radius=14)
        ul_card.grid(row=1, column=1, padx=6, sticky="nsew")
        ul_card.grid_columnconfigure(0, weight=1)
        ul_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(ul_card, text="↑  Upload", font=FONT_MED,
                     text_color=CLR_PURPLE).grid(row=0, column=0, pady=(24, 0))
        self.ul_val = ctk.CTkLabel(ul_card, text="—", font=FONT_BIG)
        self.ul_val.grid(row=1, column=0, pady=2)
        ctk.CTkLabel(ul_card, text="Mbps", font=FONT_MED,
                     text_color="gray").grid(row=2, column=0, pady=(0, 24))

        # ── Card: Ping ──────────────────────────────────────────────
        ping_card = ctk.CTkFrame(self.tab_speed, corner_radius=14)
        ping_card.grid(row=1, column=2, padx=(6, 0), sticky="nsew")
        ping_card.grid_columnconfigure(0, weight=1)
        ping_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(ping_card, text="Ping", font=FONT_MED,
                     text_color=CLR_GREEN).grid(row=0, column=0, pady=(24, 0))
        self.ping_val = ctk.CTkLabel(ping_card, text="—", font=FONT_BIG)
        self.ping_val.grid(row=1, column=0, pady=2)
        self.ping_unit = ctk.CTkLabel(ping_card, text="ms", font=FONT_MED,
                                      text_color="gray")
        self.ping_unit.grid(row=2, column=0, pady=(0, 24))

        # Server label beneath the cards
        self.server_lbl = ctk.CTkLabel(self.tab_speed, text="",
                                       font=FONT_BODY, text_color="gray")
        self.server_lbl.grid(row=2, column=0, columnspan=3, pady=(8, 0))

    def _start_speed(self):
        self.speed_btn.configure(state="disabled", text="Testing...")
        self.status_label.configure(text="Running speed test...", text_color=CLR_YELLOW)
        self.speed_status.configure(text="Connecting...")
        self.dl_val.configure(text="0.00")
        self.ul_val.configure(text="0.00")
        self.ping_val.configure(text="0.0", text_color=CLR_GREY)
        self.server_lbl.configure(text="")
        threading.Thread(target=self._speed_worker, daemon=True).start()

    def _speed_worker(self):
        def on_stage(msg):
            self.after(0, lambda: self.speed_status.configure(text=msg))

        def on_progress(metric, value, elapsed):
            self.after(0, self._speed_live_update, metric, value, elapsed)

        result = self.speed_tester.run_all(callback=on_stage, progress_callback=on_progress)
        self.after(0, self._speed_done, result)

    def _speed_live_update(self, metric, value, elapsed):
        if metric == "download":
            self.dl_val.configure(text=f"{float(value):.2f}")
            if elapsed > 0:
                self.speed_status.configure(text=f"Download: {float(value):.2f} Mbps")
            return

        if metric == "upload":
            self.ul_val.configure(text=f"{float(value):.2f}")
            if elapsed > 0:
                self.speed_status.configure(text=f"Upload: {float(value):.2f} Mbps")
            return

        if metric == "ping":
            ping = float(value)
            self.ping_val.configure(text=f"{ping:.1f}")
            self._set_ping_color(ping)
            return

        if metric == "server":
            self.server_lbl.configure(text=f"Server: {value}")

    def _set_ping_color(self, ping):
        if ping < 0:
            self.ping_val.configure(text="N/A", text_color=CLR_RED)
        elif ping < 50:
            self.ping_val.configure(text_color=CLR_GREEN)
        elif ping < 100:
            self.ping_val.configure(text_color=CLR_YELLOW)
        else:
            self.ping_val.configure(text_color=CLR_RED)

    def _speed_done(self, r):
        self.speed_btn.configure(state="normal", text="Run Speed Test")
        self.status_label.configure(text="Speed test complete", text_color=CLR_GREEN)
        self.speed_status.configure(text="Done")

        self.dl_val.configure(text=f"{float(r['download_mbps']):.2f}")
        self.ul_val.configure(text=f"{float(r['upload_mbps']):.2f}")

        ping = r["ping_ms"]
        self.ping_val.configure(text=f"{ping:.1f}" if ping >= 0 else "N/A")
        self._set_ping_color(ping)

        self.server_lbl.configure(text=f"Server: {r.get('server', '?')}")

    def _build_info_tab(self):
        self.tab_info.grid_columnconfigure(0, weight=1)
        self.tab_info.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(self.tab_info, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")

        self.info_btn = ctk.CTkButton(bar, text="Refresh Info", width=160,
                                      command=self._load_info)
        self.info_btn.pack(side="left")

        self.info_frame = ctk.CTkScrollableFrame(self.tab_info,
                                                 label_text="Network Configuration")
        self.info_frame.grid(row=1, column=0, sticky="nsew")
        self.info_frame.grid_columnconfigure(0, weight=0)
        self.info_frame.grid_columnconfigure(1, weight=1)

        # Auto-load on tab creation
        self._load_info()

    def _load_info(self):
        self.info_btn.configure(state="disabled", text="Loading…")
        self.status_label.configure(text="Gathering network info…",
                                    text_color=CLR_YELLOW)
        threading.Thread(target=self._info_worker, daemon=True).start()

    def _info_worker(self):
        data = self.net_info.collect_all()
        self.after(0, self._info_populate, data)

    def _info_populate(self, d):
        self.info_btn.configure(state="normal", text="Refresh Info")
        self.status_label.configure(text="Info loaded", text_color=CLR_GREEN)

        for w in self.info_frame.winfo_children():
            w.destroy()

        row = 0

        def _kv(label, value, color=None):
            nonlocal row
            ctk.CTkLabel(self.info_frame, text=label, font=FONT_HEADER
                         ).grid(row=row, column=0, padx=6, pady=4, sticky="w")
            ctk.CTkLabel(self.info_frame, text=str(value), font=FONT_BODY,
                         text_color=color or CLR_GREY
                         ).grid(row=row, column=1, padx=6, pady=4, sticky="w")
            row += 1

        _kv("Hostname",   d["hostname"])
        _kv("Local IP",   d["local_ip"],  CLR_BLUE)
        _kv("Public IP",  d["public_ip"], CLR_GREEN)
        _kv("Gateway",    d["gateway"])
        _kv("DNS Servers", ", ".join(d["dns"]))

        # Separator
        ctk.CTkLabel(self.info_frame, text="").grid(row=row, column=0)
        row += 1

        ctk.CTkLabel(self.info_frame, text="Network Interfaces",
                     font=FONT_HEADER, text_color=CLR_BLUE
                     ).grid(row=row, column=0, columnspan=2, padx=6, pady=(8, 4),
                            sticky="w")
        row += 1

        for iface in d["interfaces"]:
            ctk.CTkLabel(self.info_frame, text=iface["name"], font=FONT_BODY
                         ).grid(row=row, column=0, padx=6, pady=1, sticky="w")
            ctk.CTkLabel(self.info_frame, text=f"IP: {iface['ip']}   MAC: {iface['mac']}",
                         font=FONT_BODY, text_color=CLR_GREY
                         ).grid(row=row, column=1, padx=6, pady=1, sticky="w")
            row += 1


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()


