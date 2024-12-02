from scapy.all import TCP, IP, sr1, RandShort, ICMP, ARP, UDP
from multiprocessing.pool import ThreadPool
import consts
import socket
import os
import ipaddress


def CidrToIps(cidr):
    ips = []
    try:
        for ip in ipaddress.ip_network(cidr):
            ips.append(str(ip))
    except ValueError:
        pass
    return ips


def IcmpEchoScan(ip):
    response = sr1(IP(dst=ip) / ICMP(), timeout=consts.SCAN_TIMEOUT, verbose=False)
    if response:
        return ip, consts.HOST_UP
    return ip, consts.HOST_DOWN


def ArpScan(ip):
    response = sr1(ARP(pdst=ip), timeout=consts.SCAN_TIMEOUT, verbose=False)
    if response:
        return ip, consts.HOST_UP
    return ip, consts.HOST_DOWN


def ParallelHostScan(ips, callback, scan_type=IcmpEchoScan):
    pool = ThreadPool(os.cpu_count() * 4 + 1)
    for ip in ips:
        pool.apply_async(IcmpEchoScan, args=(ip,), callback=callback)
    pool.close()
    return pool


def TcpConnectScan(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(consts.SCAN_TIMEOUT)
    response = s.connect_ex((ip, port))
    s.close()
    if response == 0:
        return ip, port, consts.PORT_OPEN
    return ip, port, consts.PORT_CLOSED | consts.PORT_FILTERED


def TcpSynScan(ip, port):
    sport = RandShort()
    response = sr1(
        IP(dst=ip) / TCP(sport=sport, dport=port, flags="S"),
        timeout=consts.SCAN_TIMEOUT,
        verbose=False,
    )
    if response:
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if "S" in flags and "A" in flags:
                return ip, port, consts.PORT_OPEN
            elif "R" in flags:
                return ip, port, consts.PORT_CLOSED
    return ip, port, consts.PORT_FILTERED


def TcpFinScan(ip, port):
    sport = RandShort()
    response = sr1(
        IP(dst=ip) / TCP(sport=sport, dport=port, flags="F"),
        timeout=consts.SCAN_TIMEOUT,
        verbose=False,
    )
    if response:
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags
            if "R" in flags:
                return ip, port, consts.PORT_CLOSED
    return ip, port, consts.PORT_OPEN | consts.PORT_FILTERED


def UdpScan(ip, port):
    sport = RandShort()
    response = sr1(
        IP(dst=ip) / UDP(sport=sport, dport=port),
        timeout=consts.SCAN_TIMEOUT,
        verbose=False,
    )
    if response:
        if response.haslayer(UDP):
            return ip, port, consts.PORT_OPEN
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                return ip, port, consts.PORT_CLOSED
            else:
                return ip, port, consts.PORT_FILTERED
    return ip, port, consts.PORT_OPEN | consts.PORT_FILTERED


def ParallelPortScan(ips, ports, callback, scan_type=TcpConnectScan):
    pool = ThreadPool(os.cpu_count() * 4 + 1)
    for ip in ips:
        for port in ports:
            pool.apply_async(scan_type, args=(ip, port), callback=callback)
    pool.close()
    return pool


if __name__ == "__main__":
    print(ParallelHostScan(CidrToIps("111.186.58.0/24")))
    # print(ParallelPortScan("111.186.58.123", [80, 443, 3389, 21, 22, 23, 25565]))
    # print(
    #     ParallelPortScan(
    #         "111.186.58.123", [80, 443, 3389, 21, 22, 23, 25565], TcpSynScan
    #     )
    # )
    # print(
    #     ParallelPortScan(
    #         "111.186.58.123", [80, 443, 3389, 21, 22, 23, 25565], TcpFinScan
    #     )
    # )
