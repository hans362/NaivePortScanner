import asyncio
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

import consts
import utils

total_tasks = 0
finished_tasks = 0


def detect_hosts_callback(result):
    global total_tasks, finished_tasks
    finished_tasks += 1
    ip, status = result
    if status == consts.HOST_UP:
        tree.insert("", "end", text=ip)
    progressbar["value"] = finished_tasks / total_tasks * 100
    if finished_tasks == total_tasks:
        detect_button["state"] = "normal"
        scan_button["state"] = "normal"
        messagebox.showinfo("探测完成", "探测完成")


def detect_hosts():
    global total_tasks, finished_tasks
    cidr = cidr_entry.get()
    if not cidr:
        messagebox.showwarning("错误", "请输入有效的 CIDR")
        return
    ips = utils.CidrToIps(cidr)
    if len(ips) == 0:
        messagebox.showwarning("错误", "请输入有效的 CIDR")
        return
    detect_button["state"] = "disabled"
    scan_button["state"] = "disabled"
    total_tasks = len(ips)
    finished_tasks = 0
    tree.delete(*tree.get_children())
    utils.ParallelIcmpEchoScan(ips, detect_hosts_callback)


def scan_callback(result):
    global total_tasks, finished_tasks
    finished_tasks += 1
    ip, port, status = result
    for record in tree.get_children():
        if tree.item(record)["text"] == ip:
            break
    else:
        record = tree.insert("", "end", text=ip)
    for item in tree.get_children(record):
        if tree.item(item)["text"] == "Open":
            open = item
        elif tree.item(item)["text"] == "Filtered":
            filtered = item
        elif tree.item(item)["text"] == "Closed":
            closed = item
        elif tree.item(item)["text"] == "Open/Filtered":
            open_or_filtered = item
        elif tree.item(item)["text"] == "Closed/Filtered":
            closed_or_filtered = item
    if status == consts.PORT_OPEN:
        tree.insert(open, "end", text=f"{port}/TCP")
        tree.item(open, open=True)
        tree.item(record, open=True)
    elif status == consts.PORT_FILTERED:
        tree.insert(filtered, "end", text=f"{port}/TCP")
    elif status == consts.PORT_CLOSED:
        tree.insert(closed, "end", text=f"{port}/TCP")
    elif status == consts.PORT_OPEN | consts.PORT_FILTERED:
        tree.insert(open_or_filtered, "end", text=f"{port}/TCP")
    elif status == consts.PORT_CLOSED | consts.PORT_FILTERED:
        tree.insert(closed_or_filtered, "end", text=f"{port}/TCP")
    progressbar["value"] = finished_tasks / total_tasks * 100
    if finished_tasks == total_tasks:
        detect_button["state"] = "normal"
        scan_button["state"] = "normal"
        messagebox.showinfo("扫描完成", "扫描完成")


def scan_ports():
    global total_tasks, finished_tasks
    ips = [tree.item(record)["text"] for record in tree.get_children()]
    if len(ips) == 0:
        messagebox.showwarning("错误", "请先进行主机探测")
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
    detect_button["state"] = "disabled"
    scan_button["state"] = "disabled"
    for record in tree.get_children():
        for item in tree.get_children(record):
            tree.delete(item)
        tree.insert(record, "end", text="Open")
        tree.insert(record, "end", text="Filtered")
        tree.insert(record, "end", text="Closed")
        tree.insert(record, "end", text="Open/Filtered")
        tree.insert(record, "end", text="Closed/Filtered")
    total_tasks = len(ips) * len(ports)
    finished_tasks = 0
    utils.ParallelPortScan(ips, ports, scan_callback, scan_function)


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

detect_button = ttk.Button(root, text="主机探测", command=detect_hosts)
detect_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

scan_button = ttk.Button(root, text="端口扫描", command=scan_ports)
scan_button.grid(row=1, column=2, padx=10, pady=10, sticky="ew")


tree = ttk.Treeview(root)
tree.heading("#0", text="扫描结果")
tree.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
vsb = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
vsb.pack(side="right", fill="y")
tree.configure(yscrollcommand=vsb.set)

settings = ttk.Frame(root)
settings.grid(row=3, column=0, columnspan=3, padx=0, pady=0, sticky="ew")

detect_method = ttk.Combobox(settings)
detect_method["values"] = ("ICMP Echo 探测",)
detect_method["state"] = "readonly"
detect_method.current(0)
detect_method.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

tcp_scan_method = ttk.Combobox(settings)
tcp_scan_method["values"] = ("TCP Connect 扫描", "TCP SYN 扫描", "TCP FIN 扫描")
tcp_scan_method["state"] = "readonly"
tcp_scan_method.current(0)
tcp_scan_method.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

export_button = ttk.Button(settings, text="导出结果")
export_button.grid(row=0, column=2, padx=10, pady=10, sticky="ew")

settings.grid_columnconfigure(0, weight=1)
settings.grid_columnconfigure(1, weight=1)


progressbar = ttk.Progressbar(root, mode="determinate")
progressbar.grid(row=4, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

root.grid_rowconfigure(2, weight=1)
root.grid_columnconfigure(1, weight=1)

root.mainloop()
