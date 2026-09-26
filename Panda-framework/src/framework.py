import re
import subprocess
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import List, Optional

SCAN_REPORT_PATTERN = re.compile(
    r"Nmap scan report for (?:[^\s]+ \()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?"
)


def scan_network(network_range: str) -> List[str]:
    """Run an Nmap ping scan and return the discovered IPv4 addresses."""
    result = subprocess.run(
        ["nmap", "-sn", network_range],
        capture_output=True,
        text=True,
        check=True,
    )
    return list(dict.fromkeys(SCAN_REPORT_PATTERN.findall(result.stdout)))


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
                command=lambda target_ip=ip: self.show_device_info(target_ip),
            )
            btn.pack(fill=tk.X, pady=3)

    def show_device_info(self, ip: str) -> None:
        """Show the selected device's IP address."""
        messagebox.showinfo("Device Information", f"Selected device IP address: {ip}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapApp(root)
    root.mainloop()