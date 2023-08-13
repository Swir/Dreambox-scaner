import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
from socket import *
import threading
import json
import os

class PortScannerGUI:
    def __init__(self, window):
        self.window = window
        self.window.title("Port Scanner")
        self.window.geometry("400x600")
        self.create_widgets()
        self.scan_in_progress = False
        self.open_ports_count = 0

    def create_widgets(self):
        # IP range input fields
        ip_frame = ttk.Frame(self.window)
        ip_frame.pack(pady=10)

        self.label_start_ip = ttk.Label(ip_frame, text="Start IP:")
        self.label_start_ip.pack(side=tk.LEFT)
        self.entry_start_ip = ttk.Entry(ip_frame)
        self.entry_start_ip.pack(side=tk.LEFT)

        self.label_end_ip = ttk.Label(ip_frame, text="End IP:")
        self.label_end_ip.pack(side=tk.LEFT, padx=(10, 0))
        self.entry_end_ip = ttk.Entry(ip_frame)
        self.entry_end_ip.pack(side=tk.LEFT)

        # Port range input fields
        port_frame = ttk.Frame(self.window)
        port_frame.pack(pady=10)

        self.label_start_port = ttk.Label(port_frame, text="Start Port:")
        self.label_start_port.pack(side=tk.LEFT)
        self.entry_start_port = ttk.Entry(port_frame)
        self.entry_start_port.pack(side=tk.LEFT)

        self.label_end_port = ttk.Label(port_frame, text="End Port:")
        self.label_end_port.pack(side=tk.LEFT, padx=(10, 0))
        self.entry_end_port = ttk.Entry(port_frame)
        self.entry_end_port.pack(side=tk.LEFT)

        # Scan button
        self.scan_button = ttk.Button(self.window, text="Scan", command=self.toggle_scan)
        self.scan_button.pack(pady=10)

        # Timeout input field
        timeout_frame = ttk.Frame(self.window)
        timeout_frame.pack()

        self.label_timeout = ttk.Label(timeout_frame, text="Timeout (ms):")
        self.label_timeout.pack(side=tk.LEFT)
        self.entry_timeout = ttk.Entry(timeout_frame)
        self.entry_timeout.insert(tk.END, "1000")  # Default timeout value
        self.entry_timeout.pack(side=tk.LEFT)

        # Result treeview
        result_frame = ttk.Frame(self.window)
        result_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        self.result_treeview = ttk.Treeview(result_frame, columns=("IP", "Port"), show="headings")
        self.result_treeview.heading("IP", text="IP")
        self.result_treeview.heading("Port", text="Port")
        self.result_treeview.column("IP", width=150, anchor=tk.CENTER)
        self.result_treeview.column("Port", width=150, anchor=tk.CENTER)
        self.result_treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        result_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_treeview.yview)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_treeview.configure(yscrollcommand=result_scrollbar.set)

        # Status bar
        self.status_bar = ttk.Label(self.window, text="IPs Scanned: 0%", anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self.window, mode="determinate")
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 10))

        # Open ports counter
        self.open_ports_counter = ttk.Label(self.window, text="Open Ports: 0")
        self.open_ports_counter.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_scan(self):
        if self.scan_in_progress:
            self.stop_scan()
        else:
            self.start_scan()

    def start_scan(self):
        start_ip = self.entry_start_ip.get()
        end_ip = self.entry_end_ip.get()
        start_port = int(self.entry_start_port.get())
        end_port = int(self.entry_end_port.get())
        timeout = int(self.entry_timeout.get())

        if not start_ip or not end_ip:
            messagebox.showerror("Error", "Please enter start and end IP.")
            return

        ip_list = self.generate_ip_range(start_ip, end_ip)

        self.scan_in_progress = True
        self.scan_button.configure(text="Stop")
        self.result_treeview.delete(*self.result_treeview.get_children())
        self.status_bar.configure(text="IPs Scanned: 0%")
        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = len(ip_list)
        self.open_ports_counter.configure(text="Open Ports: 0")
        self.open_ports_count = 0

        threading.Thread(target=self.scan_ports, args=(ip_list, start_port, end_port, timeout), daemon=True).start()

    def stop_scan(self):
        self.scan_in_progress = False
        self.scan_button.configure(text="Scan")

    def scan_ports(self, ip_list, start_port, end_port, timeout):
        for i, ip in enumerate(ip_list, 1):
            if not self.scan_in_progress:
                break

            self.update_status_bar(i, len(ip_list))
            self.scan_single_ip(ip, start_port, end_port, timeout)

        self.scan_in_progress = False
        self.scan_button.configure(text="Scan")

    def scan_single_ip(self, ip, start_port, end_port, timeout):
        open_ports = []

        for port in range(start_port, end_port + 1):
            if self.port_is_open(ip, port, timeout):
                open_ports.append(port)

        self.display_scan_results(ip, open_ports)

        # Generate playlist if open ports found
        if open_ports:
            self.generate_playlist(ip, open_ports)

    def port_is_open(self, ip, port, timeout):
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.settimeout(timeout / 1000)  # Convert timeout to seconds
                result = sock.connect_ex((ip, port))
                return result == 0
        except error:
            return False

    def generate_ip_range(self, start_ip, end_ip):
        start = list(map(int, start_ip.split(".")))
        end = list(map(int, end_ip.split(".")))
        ip_range = []

        while start != end:
            ip_range.append(".".join(map(str, start)))
            start[3] += 1

            for i in (3, 2, 1):
                if start[i] == 256:
                    start[i] = 0
                    start[i - 1] += 1

        ip_range.append(".".join(map(str, start)))
        return ip_range

    def display_scan_results(self, ip, open_ports):
        if open_ports:
            for port in open_ports:
                self.result_treeview.insert("", tk.END, values=(ip, port))
                self.result_treeview.tag_bind(port, "<Button-1>",
                                          lambda event, ip=ip, port=port: self.open_port_details(ip, port))

        # Update open ports counter
        self.update_open_ports_counter(len(open_ports))

    def update_status_bar(self, scanned_count, total_count):
        percentage = int((scanned_count / total_count) * 100)
        self.status_bar.configure(text=f"IPs Scanned: {percentage}%")
        self.progress_bar["value"] = scanned_count
        self.window.update()

    def generate_playlist(self, ip, open_ports):
        playlist_template = self.load_playlist_template()
        playlist = playlist_template.replace("xxx.xxx.xxx.xxx", ip)

        # Save playlist to file
        playlist_filename = f"HITS/playlist_{ip.replace('.', '_')}.m3u"
        with open(playlist_filename, "w") as file:
            file.write(playlist)

    def load_playlist_template(self):
        template_filename = "playlist_template.m3u"

        if not os.path.isfile(template_filename):
            default_template = "# Playlist Template\n# Replace 'xxx.xxx.xxx.xxx' with the IP address\n\n"
            with open(template_filename, "w") as file:
                file.write(default_template)

        with open(template_filename, "r") as file:
            return file.read()

    def open_port_details(self, ip, port):
        messagebox.showinfo("Port Details", f"IP: {ip}\nPort: {port}")

    def update_open_ports_counter(self, count):
        self.open_ports_count += count
        self.open_ports_counter.configure(text=f"Open Ports: {self.open_ports_count}")


if __name__ == "__main__":
    window = tk.Tk()
    app = PortScannerGUI(window)
    window.mainloop()
