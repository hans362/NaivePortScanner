import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

import consts
import utils


def detect_hosts():
    cidr = cidr_entry.get()
    ports = ports_entry.get()
    if not cidr or not ports:
        messagebox.showwarning("错误", "请输入有效的 CIDR 和端口范围")
        return
    ips = utils.CidrToIps(cidr)
    if len(ips) == 0:
        messagebox.showwarning("错误", "请输入有效的 CIDR")
        return
    tree.delete(*tree.get_children())
    results = utils.ParallelIcmpEchoScan(ips)
    for i, result in enumerate(results):
        if result == consts.HOST_UP:
            tree.insert("", "end", text=ips[i])
    messagebox.showinfo("扫描完成", "扫描完成")


def scan_ports():
    ips = [item for item in tree.get_children()]
    if len(ips) == 0:
        messagebox.showwarning("错误", "请先探测存活主机")
        return
    ports = []
    for port in ports_entry.get().split(","):
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError
            ports.append(port)
        except ValueError:
            messagebox.showwarning("输入错误", "请输入有效的端口范围")
            return
    scan_type = tcp_scan_method.get()
    if scan_type == "TCP Connect 扫描":
        scan_function = utils.TcpConnectScan
    elif scan_type == "TCP SYN 扫描":
        scan_function = utils.TcpSynScan
    elif scan_type == "TCP FIN 扫描":
        scan_function = utils.TcpFinScan
    else:
        messagebox.showwarning("错误", "请选择有效的扫描方法")
        return
    for record in ips:
        ip = tree.item(record)["text"]
        open_ports = utils.ParallelPortScan(ip, ports, scan_function)
        for item in tree.get_children(record):
            tree.delete(item)
        tree.item(record, open=True)
        open = tree.insert(record, "end", text="Open")
        filtered = tree.insert(record, "end", text="Filtered")
        closed = tree.insert(record, "end", text="Closed")
        open_or_filtered = tree.insert(record, "end", text="Open/Filtered")
        closed_or_filtered = tree.insert(record, "end", text="Closed/Filtered")
        for port, status in zip(ports, open_ports):
            if status == consts.PORT_OPEN:
                tree.insert(open, "end", text=f"{port}/TCP")
                tree.item(open, open=True)
            elif status == consts.PORT_FILTERED:
                tree.insert(filtered, "end", text=f"{port}/TCP")
            elif status == consts.PORT_CLOSED:
                tree.insert(closed, "end", text=f"{port}/TCP")
            elif status == consts.PORT_OPEN | consts.PORT_FILTERED:
                tree.insert(open_or_filtered, "end", text=f"{port}/TCP")
            elif status == consts.PORT_CLOSED | consts.PORT_FILTERED:
                tree.insert(closed_or_filtered, "end", text=f"{port}/TCP")
    messagebox.showinfo("扫描完成", "扫描完成")


root = ttk.Window(themename="superhero")
root.title("NaivePortScanner")
root.geometry("1024x768")

ttk.Label(root, text="IP CIDR").grid(row=0, column=0, padx=10, pady=10, sticky="ew")
cidr_entry = ttk.Entry(root)
cidr_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

ttk.Label(root, text="端口范围").grid(row=1, column=0, padx=10, pady=10, sticky="ew")
ports_entry = ttk.Entry(root)
ports_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
ports_entry.insert(0, consts.DEFAULT_PORT_RANGE)

detect_button = ttk.Button(root, text="探测存活主机", command=detect_hosts)
detect_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

scan_button = ttk.Button(root, text="开始端口扫描", command=scan_ports)
scan_button.grid(row=1, column=2, padx=10, pady=10, sticky="ew")


tree = ttk.Treeview(root)
tree.heading("#0", text="扫描结果")
tree.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

tcp_scan_method = ttk.Combobox(root)
tcp_scan_method["values"] = ("TCP Connect 扫描", "TCP SYN 扫描", "TCP FIN 扫描")
tcp_scan_method.current(0)
tcp_scan_method.grid(row=3, column=0, padx=10, pady=10, sticky="ew")


progressbar = ttk.Progressbar(root, mode="determinate")
progressbar.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

root.grid_rowconfigure(2, weight=1)
root.grid_columnconfigure(1, weight=1)

root.mainloop()
