import re
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

SCAN_REPORT_PATTERN = re.compile(
    r"Nmap scan report for (?:[^\s]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?"
)
PORT_PATTERN = re.compile(
    r"^\s*(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)\s*(.*)$",
    re.IGNORECASE,
)
OS_RUNNING_PATTERN = re.compile(r"Running:\s*(.*)", re.IGNORECASE)
OS_DETAILS_PATTERN = re.compile(r"OS details:\s*(.*)", re.IGNORECASE)
MAC_PATTERN = re.compile(r"MAC Address:\s*([^\s]+)\s+(.*)", re.IGNORECASE)


def scan_network(network_range: str) -> List[str]:
    """Run an Nmap ping scan and return the discovered IPv4 addresses."""
    result = subprocess.run(
        ["nmap", "-sn", network_range],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(dict.fromkeys(SCAN_REPORT_PATTERN.findall(result.stdout)))


def port_scan(ip: str) -> str:
    """Run an Nmap port scan on a specific IP address."""
    result = subprocess.run(
        ["nmap", ip],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def passive_scan(ip: str) -> str:
    """Run a passive scan on a specific IP address using OS detection."""
    result = subprocess.run(
        ["nmap", "-O", ip],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def parse_open_ports(output: str) -> List[dict]:
    """Extract open TCP/UDP ports and service names from an Nmap output."""
    ports = []
    for line in output.splitlines():
        match = PORT_PATTERN.match(line)
        if match:
            port, protocol, state, service, extra = match.groups()
            if state.lower() == "open":
                ports.append(
                    {
                        "port": int(port),
                        "protocol": protocol.lower(),
                        "state": state.lower(),
                        "service": service,
                        "details": extra.strip(),
                    }
                )
    return ports


def parse_device_info(output: str) -> dict:
    """Extract basic OS and host information from Nmap output."""
    info = {
        "os": "Unknown",
        "running": "Unknown",
        "mac": "Unknown",
    }
    os_match = OS_DETAILS_PATTERN.search(output)
    if os_match:
        info["os"] = os_match.group(1).strip()

    running_match = OS_RUNNING_PATTERN.search(output)
    if running_match:
        info["running"] = running_match.group(1).strip()

    mac_match = MAC_PATTERN.search(output)
    if mac_match:
        info["mac"] = mac_match.group(1).strip()

    return info


class NmapApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap Network Scanner")
        self.root.geometry("450x500")

        input_frame = ttk.Frame(root, padding=10)
        input_frame.pack(fill=tk.X)

        ttk.Label(
            input_frame,
            text="Network range (e.g. 192.168.1.0/24):",
        ).pack(anchor=tk.W)

        self.ip_entry = ttk.Entry(input_frame, width=30)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.pack(side=tk.LEFT, pady=5, padx=(0, 5))

        self.scan_button = ttk.Button(
            input_frame,
            text="Start Scan",
            command=self.start_scan,
        )
        self.scan_button.pack(side=tk.LEFT, pady=5)

        self.status_label = ttk.Label(
            root,
            text="Status: Ready",
            font=("Arial", 10, "italic"),
        )
        self.status_label.pack(pady=5)

        self.results_frame = ttk.LabelFrame(root, text="Discovered Devices", padding=10)
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.context_menu = tk.Menu(root, tearoff=0)
        self.context_menu.add_command(label="Port Scan", command=self.on_port_scan)
        self.context_menu.add_command(label="Passive Scan", command=self.on_passive_scan)
        self.context_menu.add_command(label="Device Info", command=self.on_device_info)

        self.selected_ip = None
        self.scan_history = {}

    def start_scan(self):
        network_range = self.ip_entry.get().strip()
        if not network_range:
            messagebox.showwarning(
                "Invalid Network Range",
                "Enter a network range to scan.",
            )
            return

        self.scan_button.config(state=tk.DISABLED)
        self.status_label.config(text="Scanning network...")

        for widget in self.results_frame.winfo_children():
            widget.destroy()

        threading.Thread(
            target=self._scan_in_background,
            args=(network_range,),
            daemon=True,
        ).start()

    def _scan_in_background(self, network_range: str) -> None:
        try:
            devices = scan_network(network_range)
            error_message = None
        except FileNotFoundError:
            devices = []
            error_message = (
                "Nmap was not found. Make sure it is installed and available on PATH."
            )
        except subprocess.CalledProcessError as error:
            devices = []
            error_message = f"Nmap scan failed:\n{error.stderr or error}"
        except Exception as exc:
            devices = []
            error_message = str(exc)
        self.root.after(0, self._update_ui, devices, error_message)

    def _update_ui(self, devices: List[str], error_message: Optional[str]) -> None:
        self.scan_button.config(state=tk.NORMAL)
        if error_message:
            self.status_label.config(text="Scan failed")
            messagebox.showerror("Scan Error", error_message)
            return

        if not devices:
            self.status_label.config(text="No active devices found.")
            return

        self.status_label.config(text=f"Found {len(devices)} active device(s).")

        for ip in devices:
            btn = ttk.Button(
                self.results_frame,
                text=ip,
                command=lambda target_ip=ip: self.show_device_menu(target_ip),
            )
            btn.pack(fill=tk.X, pady=3)
            btn.bind("<Button-3>", lambda event, target_ip=ip: self.show_context_menu(event, target_ip))

    def show_context_menu(self, event, ip: str) -> None:
        """Display the context menu when right-clicking on a device."""
        self.selected_ip = ip
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def show_device_menu(self, ip: str) -> None:
        """Show menu with device options when left-clicking."""
        self.selected_ip = ip
        menu_window = tk.Toplevel(self.root)
        menu_window.title(f"Device Options - {ip}")
        menu_window.geometry("300x180")
        menu_window.resizable(False, False)

        ttk.Label(menu_window, text=f"IP Address: {ip}", font=("Arial", 10, "bold")).pack(pady=10)

        ttk.Button(
            menu_window,
            text="Port Scan",
            command=self.on_port_scan,
        ).pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(
            menu_window,
            text="Passive Scan",
            command=self.on_passive_scan,
        ).pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(
            menu_window,
            text="Device Info",
            command=self.on_device_info,
        ).pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(
            menu_window,
            text="Close",
            command=menu_window.destroy,
        ).pack(fill=tk.X, padx=10, pady=5)

    def on_port_scan(self) -> None:
        """Execute port scan on the selected device."""
        if not self.selected_ip:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return

        self.status_label.config(text=f"Port scanning {self.selected_ip}...")
        threading.Thread(
            target=self._port_scan_background,
            args=(self.selected_ip,),
            daemon=True,
        ).start()

    def _port_scan_background(self, ip: str) -> None:
        try:
            output = port_scan(ip)
            error_message = None
            ports = parse_open_ports(output)
            info = parse_device_info(output)
        except FileNotFoundError:
            output = ""
            error_message = "Nmap was not found. Make sure it is installed and available on PATH."
            ports = []
            info = {}
        except subprocess.CalledProcessError as error:
            output = ""
            error_message = f"Port scan failed:\n{error.stderr or error}"
            ports = []
            info = {}
        except Exception as exc:
            output = ""
            error_message = str(exc)
            ports = []
            info = {}

        self.root.after(
            0,
            self._show_scan_results,
            "Port Scan Results",
            ip,
            output,
            error_message,
            ports,
            info,
        )

    def on_passive_scan(self) -> None:
        """Execute passive scan on the selected device."""
        if not self.selected_ip:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return

        self.status_label.config(text=f"Passive scanning {self.selected_ip}...")
        threading.Thread(
            target=self._passive_scan_background,
            args=(self.selected_ip,),
            daemon=True,
        ).start()

    def _passive_scan_background(self, ip: str) -> None:
        try:
            output = passive_scan(ip)
            error_message = None
            ports = parse_open_ports(output)
            info = parse_device_info(output)
        except FileNotFoundError:
            output = ""
            error_message = "Nmap was not found. Make sure it is installed and available on PATH."
            ports = []
            info = {}
        except subprocess.CalledProcessError as error:
            output = ""
            error_message = f"Passive scan failed:\n{error.stderr or error}"
            ports = []
            info = {}
        except Exception as exc:
            output = ""
            error_message = str(exc)
            ports = []
            info = {}

        self.root.after(
            0,
            self._show_scan_results,
            "Passive Scan Results",
            ip,
            output,
            error_message,
            ports,
            info,
        )

    def on_device_info(self) -> None:
        """Show the selected device's information."""
        if not self.selected_ip:
            messagebox.showwarning("No Device Selected", "Please select a device first.")
            return

        ip = self.selected_ip
        scan_output = self.scan_history.get(ip, "")
        info = parse_device_info(scan_output)
        ports = parse_open_ports(scan_output)
        self._show_device_details(ip, info, ports)

    def _show_device_details(self, ip: str, info: dict, ports: List[dict]) -> None:
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Device Info - {ip}")
        details_window.geometry("420x420")

        ttk.Label(details_window, text=f"Device Information: {ip}", font=("Arial", 12, "bold")).pack(pady=10)

        info_frame = ttk.Frame(details_window, padding=10)
        info_frame.pack(fill=tk.X, padx=10)

        fields = [
            ("IP Address", ip),
            ("OS", info.get("os", "Unknown")),
            ("Running", info.get("running", "Unknown")),
            ("MAC", info.get("mac", "Unknown")),
            ("Open Ports", str(len(ports)) if ports else "0"),
        ]

        for label, value in fields:
            ttk.Label(info_frame, text=f"{label}:", font=("Arial", 9, "bold")).pack(anchor=tk.W)
            ttk.Label(info_frame, text=str(value), wraplength=360).pack(anchor=tk.W, pady=(0, 5))

        ports_frame = ttk.LabelFrame(details_window, text="Open Ports / Services", padding=10)
        ports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        if not ports:
            ttk.Label(ports_frame, text="No open ports detected.").pack(anchor=tk.W)
        else:
            for port in ports:
                port_text = (
                    f"{port['port']}/{port['protocol']} - {port['service']}"
                    f" ({port['state']})"
                )
                if port.get("details"):
                    port_text += f" - {port['details']}"
                ttk.Label(ports_frame, text=port_text, wraplength=330).pack(anchor=tk.W, pady=2)

        ttk.Button(details_window, text="Close", command=details_window.destroy).pack(pady=10)

    def _show_scan_results(
        self,
        title: str,
        ip: str,
        output: str,
        error_message: Optional[str],
        ports: List[dict],
        info: dict,
    ) -> None:
        """Display scan results in a new window."""
        if error_message:
            self.status_label.config(text="Scan failed")
            messagebox.showerror(f"{title} - Error", error_message)
            return

        self.status_label.config(text="Scan completed")
        self.scan_history[ip] = output

        results_window = tk.Toplevel(self.root)
        results_window.title(f"{title} - {ip}")
        results_window.geometry("650x480")

        ttk.Label(results_window, text=f"{title} for {ip}", font=("Arial", 12, "bold")).pack(pady=10)

        summary_frame = ttk.LabelFrame(results_window, text="Summary", padding=10)
        summary_frame.pack(fill=tk.X, padx=10)

        summary_text = f"Open ports: {len(ports)} | OS: {info.get('os', 'Unknown')} | Running: {info.get('running', 'Unknown')}"
        ttk.Label(summary_frame, text=summary_text, wraplength=600).pack(anchor=tk.W)

        text_frame = ttk.Frame(results_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        results_text = tk.Text(text_frame, yscrollcommand=scrollbar.set, wrap=tk.WORD)
        results_text.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=results_text.yview)

        results_text.insert(tk.END, output)
        results_text.config(state=tk.DISABLED)

        action_frame = ttk.Frame(results_window)
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        ttk.Button(
            action_frame,
            text="Save Results",
            command=lambda: self._save_scan_results(ip, output),
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            action_frame,
            text="Device Info",
            command=lambda: self._show_device_details(ip, info, ports),
        ).pack(side=tk.LEFT)

        ttk.Button(
            action_frame,
            text="Close",
            command=results_window.destroy,
        ).pack(side=tk.RIGHT)

    def _save_scan_results(self, ip: str, output: str) -> None:
        """Save the raw Nmap output for a selected device."""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"nmap_{ip.replace('.', '_')}_scan.txt",
            title="Save scan results",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(output)
            messagebox.showinfo("Saved", f"Scan results saved to:\n{file_path}")
        except Exception as exc:
            messagebox.showerror("Save Error", f"Failed to save file:\n{exc}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NmapApp(root)
    root.mainloop()
