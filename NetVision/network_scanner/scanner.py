import scapy.all as scapy
import requests
import socket
import ipaddress
import time
import threading

class PacketSniffer:
    """Live packet sniffer using scapy."""

    def __init__(self):
        self.packets = []
        self._sniffing = False
        self._thread = None

    @property
    def is_sniffing(self):
        return self._sniffing

    def start(self, callback=None, count=0):
        """
        Start sniffing in a background thread.
        :param callback: Called with a packet dict for every captured packet.
        :param count: Max packets to capture (0 = unlimited).
        """
        if self._sniffing:
            return
        self._sniffing = True
        self.packets = []
        self._thread = threading.Thread(
            target=self._sniff_loop, args=(callback, count), daemon=True
        )
        self._thread.start()

    def stop(self):
        self._sniffing = False

    def _sniff_loop(self, callback, count):
        try:
            scapy.sniff(
                prn=lambda pkt: self._process_packet(pkt, callback),
                stop_filter=lambda _: not self._sniffing,
                count=count if count > 0 else 0,
                store=False,
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
        finally:
            self._sniffing = False

    def _process_packet(self, pkt, callback):
        info = self._summarize(pkt)
        self.packets.append(info)
        if callback:
            callback(info)

    @staticmethod
    def _summarize(pkt):
        """Return a dict summarising one packet."""
        ts = time.strftime("%H:%M:%S")
        src = dst = proto = ""
        length = len(pkt)

        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
        elif pkt.haslayer(scapy.ARP):
            src = pkt[scapy.ARP].psrc
            dst = pkt[scapy.ARP].pdst

        if pkt.haslayer(scapy.TCP):
            proto = "TCP"
        elif pkt.haslayer(scapy.UDP):
            proto = "UDP"
        elif pkt.haslayer(scapy.ICMP):
            proto = "ICMP"
        elif pkt.haslayer(scapy.ARP):
            proto = "ARP"
        elif pkt.haslayer(scapy.DNS):
            proto = "DNS"
        else:
            proto = "Other"

        # One-line summary
        summary = pkt.summary() if hasattr(pkt, "summary") else ""

        return {
            "time": ts,
            "src": src,
            "dst": dst,
            "protocol": proto,
            "length": length,
            "info": summary,
        }


class NetworkScanner:
    def __init__(self):
        self.devices = []

    def get_local_ip_range(self):
        """
        Detects the local IP range (CIDR) based on the machine's IP address.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Assuming /24 subnet for simplicity, a more robust method uses netifaces
            # but that adds another dependency. This is a common heuristic for home networks.
            ip_obj = ipaddress.IPv4Interface(f"{local_ip}/24")
            return str(ip_obj.network)
        except Exception as e:
            print(f"Could not determine local IP: {e}")
            return "192.168.1.0/24" # Fallback

    def scan(self, ip_range=None):
        """
        Scans the network for devices using ARP requests.
        :param ip_range: IP range to scan (e.g., "192.168.1.0/24"). If None, detects automatically.
        :return: List of dictionaries containing IP, MAC, and Vendor
        """
        if ip_range is None:
            ip_range = self.get_local_ip_range()

        print(f"Scanning range: {ip_range}")
        self.devices = []
        try:
            # scapy.arping returns a tuple (answered, unanswered)
            # scapy.srp sends and receives packets at layer 2
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # verbose=0 suppresses output meant for stdout
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=0)[0]

            for element in answered_list:
                mac_address = element[1].hwsrc
                vendor = self.get_vendor(mac_address)
                device_info = {
                    "ip": element[1].psrc,
                    "mac": mac_address,
                    "vendor": vendor
                }
                self.devices.append(device_info)
            return self.devices
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []

    def get_vendor(self, mac_address):
        """
        Retrieves the vendor of a device using its MAC address via an online API.
        Current API: macvendors.com (limit 1 request per second typically, need to handle slowly or verify limits)
        Alternate: macvendors.co
        """
        try:
            # API rate limits can be an issue. 
            # Ideally we'd have a local database, but for a simple app we'll try an API.
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=2) # Short timeout to not block scan too long
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown Vendor"
        except Exception:
            return "Unknown Vendor"

if __name__ == "__main__":
    scanner = NetworkScanner()
    print("Starting scan...")
    devices = scanner.scan()
    print("Devices found:")
    for device in devices:
        print(device)


# ═══════════════════════════════════════════════════════════════════════
#  PORT SCANNER
# ═══════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1434: "MSSQL-UDP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def parse_ports_spec(spec):
    """
    Parse a ports string like "22,80,443,8000-8100" into a sorted unique list.
    Empty input falls back to COMMON_PORTS keys.
    """
    if not spec or not spec.strip():
        return sorted(COMMON_PORTS.keys())

    ports = set()
    for token in spec.split(","):
        item = token.strip()
        if not item:
            raise ValueError("Empty item in ports list.")

        if "-" in item:
            start_text, end_text = [part.strip() for part in item.split("-", 1)]
            if not start_text or not end_text:
                raise ValueError(f"Invalid range: '{item}'.")
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Range must be numeric: '{item}'.")

            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Range start must be <= end: '{item}'.")
            if start < 1 or end > 65535:
                raise ValueError(f"Port out of range in '{item}' (1-65535).")

            for port in range(start, end + 1):
                ports.add(port)
        else:
            if not item.isdigit():
                raise ValueError(f"Port must be numeric: '{item}'.")
            port = int(item)
            if port < 1 or port > 65535:
                raise ValueError(f"Port out of range: '{item}' (1-65535).")
            ports.add(port)

    if not ports:
        raise ValueError("No ports to scan.")

    return sorted(ports)


class PortScanner:
    """TCP connect() port scanner."""

    def scan(self, target, ports=None, timeout=0.5, callback=None):
        """
        Scan *target* for open TCP ports.
        :param target:   IP or hostname
        :param ports:    iterable of port numbers (default: COMMON_PORTS keys)
        :param timeout:  connect timeout per port
        :param callback: called with (port, service, "open"/"closed") per port
        :return: list of dicts for open ports
        """
        if ports is None:
            ports = sorted(COMMON_PORTS.keys())

        open_ports = []
        for port in ports:
            service = COMMON_PORTS.get(port, "Unknown")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                result = s.connect_ex((target, port))
                s.close()
                if result == 0:
                    open_ports.append({"port": port, "service": service, "state": "open"})
                    if callback:
                        callback(port, service, "open")
                else:
                    if callback:
                        callback(port, service, "closed")
            except Exception:
                if callback:
                    callback(port, service, "error")

        return open_ports


# ═══════════════════════════════════════════════════════════════════════
#  SPEED TESTER  (Custom Multi-threaded Implementation)
# ═══════════════════════════════════════════════════════════════════════

class SpeedTester:
    """
    Custom speed tester (no external speedtest library).
    Uses multi-connection transfer with warm-up and timed sampling.
    """

    PROVIDERS = [
        {
            "name": "Cloudflare",
            "ping_host": "speed.cloudflare.com",
            "down_template": "https://speed.cloudflare.com/__down?bytes={bytes}",
            "up_url": "https://speed.cloudflare.com/__up",
            "up_mode": "raw",
            "max_down_bytes": 90_000_000,
        },
        {
            "name": "Tele2",
            "ping_host": "speedtest.tele2.net",
            "down_template": "http://speedtest.tele2.net/100MB.zip?seed={seed}",
            "up_url": "http://speedtest.tele2.net/upload.php",
            "up_mode": "multipart",
            "max_down_bytes": 100_000_000,
        },
    ]

    # Tuned defaults for better peak detection.
    PING_COUNT = 6
    WARMUP_SECONDS = 2
    DOWNLOAD_SECONDS = 14
    UPLOAD_SECONDS = 12
    DOWNLOAD_THREADS = 10
    UPLOAD_THREADS = 5
    DOWNLOAD_CHUNK = 256 * 1024
    UPLOAD_CHUNK = 2 * 1024 * 1024

    def __init__(self):
        self._stop_event = threading.Event()
        self._provider = None

    def run_all(self, callback=None, progress_callback=None):
        """
        Run download, upload, and ping tests.
        :param callback: fn(status_msg)
        :return: dict with results
        """
        self._stop_event.clear()

        if callback:
            callback("Selecting test server...")
        provider = self._select_provider()
        self._provider = provider
        if progress_callback:
            try:
                progress_callback("server", provider["name"], 0.0)
                progress_callback("download", 0.0, 0.0)
                progress_callback("upload", 0.0, 0.0)
            except Exception:
                pass

        # 1. Ping
        if callback:
            callback("Pinging server...")
        ping = self.measure_ping(
            count=self.PING_COUNT,
            host=provider["ping_host"],
            progress_callback=progress_callback,
        )

        # 2. Download
        if callback:
            callback("Testing download...")
        dl_mbps = self.measure_download(
            duration=self.DOWNLOAD_SECONDS,
            warmup=self.WARMUP_SECONDS,
            threads=self.DOWNLOAD_THREADS,
            chunk_size=self.DOWNLOAD_CHUNK,
            progress_callback=progress_callback,
        )

        # 3. Upload
        if callback:
            callback("Testing upload...")
        ul_mbps = self.measure_upload(
            duration=self.UPLOAD_SECONDS,
            warmup=self.WARMUP_SECONDS,
            threads=self.UPLOAD_THREADS,
            chunk_size=self.UPLOAD_CHUNK,
            progress_callback=progress_callback,
        )

        return {
            "download_mbps": dl_mbps,
            "upload_mbps": ul_mbps,
            "ping_ms": ping,
            "server": provider["name"],
        }

    def _provider_down_url(self, provider, num_bytes):
        if provider["name"] == "Cloudflare":
            return provider["down_template"].format(bytes=int(num_bytes), seed="")
        return provider["down_template"].format(bytes=int(num_bytes), seed=time.time_ns())

    def _probe_provider(self, provider, probe_bytes=800_000):
        """
        Quick throughput probe used to select the best provider for this session.
        Returns Mbps estimate (higher is better).
        """
        try:
            url = self._provider_down_url(provider, probe_bytes)
            t0 = time.perf_counter()
            got = 0
            with requests.get(
                url, stream=True, timeout=(3, 8), headers={"Cache-Control": "no-cache"}
            ) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    got += len(chunk)
                    if got >= probe_bytes:
                        break
            elapsed = max(0.001, time.perf_counter() - t0)
            return (got * 8) / (elapsed * 1_000_000)
        except Exception:
            return -1.0

    def _select_provider(self):
        best = self.PROVIDERS[0]
        best_score = -1.0
        for provider in self.PROVIDERS:
            score = self._probe_provider(provider)
            if score > best_score:
                best = provider
                best_score = score
        return best

    def measure_ping(self, count=4, host=None, progress_callback=None):
        """Average TCP connect latency (trimmed mean) to reduce jitter spikes."""
        host = host or (self._provider["ping_host"] if self._provider else self.PROVIDERS[0]["ping_host"])
        rtts = []
        for _ in range(count):
            try:
                t0 = time.perf_counter()
                with socket.create_connection((host, 443), timeout=2):
                    pass
                rtt = (time.perf_counter() - t0) * 1000
                rtts.append(rtt)
                if progress_callback:
                    try:
                        progress_callback("ping", round(rtt, 1), len(rtts))
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(0.12)

        if not rtts:
            return -1

        rtts.sort()
        if len(rtts) >= 5:
            rtts = rtts[1:-1]  # drop one best + one worst sample
        return round(sum(rtts) / len(rtts), 1)

    def measure_download(
        self,
        duration=10,
        warmup=2,
        threads=4,
        chunk_size=65536,
        progress_callback=None,
    ):
        """
        Download from multiple threads with warm-up.
        Returns speed in Mbps.
        """
        test_start = time.perf_counter()
        count_start = test_start + max(0, warmup)
        stop_at = count_start + max(1, duration)
        provider = self._provider or self.PROVIDERS[0]

        total_bytes = [0]
        lock = threading.Lock()
        last_emit = [0.0]

        def _emit_progress(now, force=False):
            if not progress_callback:
                return
            if now < count_start:
                return
            if not force and now - last_emit[0] < 0.25:
                return
            with lock:
                byte_count = total_bytes[0]
            elapsed = max(0.001, now - count_start)
            mbps = (byte_count * 8) / (elapsed * 1_000_000)
            last_emit[0] = now
            try:
                progress_callback("download", round(mbps, 2), elapsed)
            except Exception:
                pass

        def _worker(worker_id):
            session = requests.Session()
            while time.perf_counter() < stop_at and not self._stop_event.is_set():
                try:
                    target_bytes = provider.get("max_down_bytes", 100_000_000)
                    url = self._provider_down_url(provider, target_bytes)
                    with session.get(
                        url,
                        stream=True,
                        timeout=(3, 8),
                        headers={"Cache-Control": "no-cache"},
                    ) as r:
                        r.raise_for_status()
                        for chunk in r.iter_content(chunk_size=chunk_size):
                            now = time.perf_counter()
                            if now >= stop_at or self._stop_event.is_set():
                                break
                            if chunk and now >= count_start:
                                with lock:
                                    total_bytes[0] += len(chunk)
                                _emit_progress(now)
                except Exception:
                    time.sleep(0.1)
            session.close()

        pool = [
            threading.Thread(target=_worker, args=(idx,), daemon=True)
            for idx in range(max(1, threads))
        ]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        _emit_progress(min(time.perf_counter(), stop_at), force=True)
        measured_elapsed = max(0.001, min(time.perf_counter(), stop_at) - count_start)
        mbps = (total_bytes[0] * 8) / (measured_elapsed * 1_000_000)
        return round(mbps, 2)

    def measure_upload(
        self,
        duration=10,
        warmup=2,
        threads=2,
        chunk_size=1048576,
        progress_callback=None,
    ):
        """
        Upload random payloads from multiple threads with warm-up.
        Returns speed in Mbps.
        """
        test_start = time.perf_counter()
        count_start = test_start + max(0, warmup)
        stop_at = count_start + max(1, duration)
        provider = self._provider or self.PROVIDERS[0]

        total_bytes = [0]
        lock = threading.Lock()
        data_chunk = b"x" * max(64 * 1024, chunk_size)
        last_emit = [0.0]

        def _emit_progress(now, force=False):
            if not progress_callback:
                return
            if now < count_start:
                return
            if not force and now - last_emit[0] < 0.25:
                return
            with lock:
                byte_count = total_bytes[0]
            elapsed = max(0.001, now - count_start)
            mbps = (byte_count * 8) / (elapsed * 1_000_000)
            last_emit[0] = now
            try:
                progress_callback("upload", round(mbps, 2), elapsed)
            except Exception:
                pass

        def _worker():
            session = requests.Session()
            while time.perf_counter() < stop_at and not self._stop_event.is_set():
                try:
                    if provider["up_mode"] == "raw":
                        response = session.post(
                            provider["up_url"],
                            data=data_chunk,
                            headers={"Content-Type": "application/octet-stream"},
                            timeout=(3, 8),
                        )
                    else:
                        response = session.post(
                            provider["up_url"],
                            files={"file": ("blob.bin", data_chunk, "application/octet-stream")},
                            timeout=(3, 8),
                        )
                    ok = response.status_code < 400
                    response.close()
                    if ok and time.perf_counter() >= count_start:
                        with lock:
                            total_bytes[0] += len(data_chunk)
                        _emit_progress(time.perf_counter())
                except Exception:
                    time.sleep(0.1)
            session.close()

        pool = [threading.Thread(target=_worker, daemon=True) for _ in range(max(1, threads))]
        for t in pool:
            t.start()
        for t in pool:
            t.join()

        _emit_progress(min(time.perf_counter(), stop_at), force=True)
        measured_elapsed = max(0.001, min(time.perf_counter(), stop_at) - count_start)
        mbps = (total_bytes[0] * 8) / (measured_elapsed * 1_000_000)
        return round(mbps, 2)
# ═══════════════════════════════════════════════════════════════════════
#  NETWORK INFO  (local connection details)
# ═══════════════════════════════════════════════════════════════════════

import subprocess
import re
import platform


class NetworkInfo:
    """Gather information about the local network configuration."""

    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "N/A"

    @staticmethod
    def get_public_ip():
        try:
            return requests.get("https://api.ipify.org", timeout=5).text
        except Exception:
            return "N/A"

    @staticmethod
    def get_hostname():
        return socket.gethostname()

    @staticmethod
    def get_gateway_and_dns():
        """Parse ipconfig (Windows) or ip route (Linux/Mac) for gateway + DNS."""
        gateway = "N/A"
        dns_servers = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    "ipconfig /all", shell=True, text=True, stderr=subprocess.DEVNULL
                )
                # Gateway
                gw_match = re.search(r"Default Gateway.*?:\s*([\d.]+)", output)
                if gw_match:
                    gateway = gw_match.group(1)
                # DNS
                for m in re.finditer(r"DNS Servers.*?:\s*([\d.]+)", output):
                    dns_servers.append(m.group(1))
                # Sometimes multiple DNS on consecutive lines
                for m in re.finditer(r"^\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)\s*$", output, re.M):
                    if m.group(1) not in dns_servers:
                        dns_servers.append(m.group(1))
            else:
                gw = subprocess.check_output(
                    "ip route | grep default", shell=True, text=True
                )
                gw_match = re.search(r"default via ([\d.]+)", gw)
                if gw_match:
                    gateway = gw_match.group(1)
                try:
                    with open("/etc/resolv.conf") as f:
                        for line in f:
                            m = re.match(r"nameserver\s+([\d.]+)", line)
                            if m:
                                dns_servers.append(m.group(1))
                except Exception:
                    pass
        except Exception:
            pass

        return gateway, dns_servers if dns_servers else ["N/A"]

    @staticmethod
    def get_interfaces():
        """Return a list of dicts with interface name, IP, and MAC."""
        interfaces = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    "ipconfig /all", shell=True, text=True, stderr=subprocess.DEVNULL
                )
                # Split by adapter sections
                sections = re.split(r"\r?\n(?=\S.*adapter )", output)
                for section in sections:
                    name_match = re.search(r"^(.+adapter .+?):", section)
                    ip_match   = re.search(r"IPv4 Address.*?:\s*([\d.]+)", section)
                    mac_match  = re.search(r"Physical Address.*?:\s*([\w-]+)", section)
                    if name_match:
                        interfaces.append({
                            "name": name_match.group(1).strip(),
                            "ip":   ip_match.group(1) if ip_match else "—",
                            "mac":  mac_match.group(1) if mac_match else "—",
                        })
            else:
                output = subprocess.check_output(
                    "ip -br addr", shell=True, text=True
                )
                for line in output.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        interfaces.append({
                            "name": parts[0],
                            "ip":   parts[2].split("/")[0] if "/" in parts[2] else parts[2],
                            "mac":  "—",
                        })
        except Exception:
            pass
        return interfaces

    def collect_all(self):
        gateway, dns = self.get_gateway_and_dns()
        return {
            "hostname":   self.get_hostname(),
            "local_ip":   self.get_local_ip(),
            "public_ip":  self.get_public_ip(),
            "gateway":    gateway,
            "dns":        dns,
            "interfaces": self.get_interfaces(),
        }
