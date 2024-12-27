# NaivePortScanner 项目文档

## 概述

一款具有图形化界面的端口扫描器

- 支持基于 ICMP 请求、ARP 请求探测存活主机
- 支持 TCP Connect 扫描、TCP SYN 扫描、TCP FIN 扫描、UDP 扫描四种扫描方式
- 支持指定 IP CIDR 和端口范围进行批量扫描
- 支持 HTTP、FTP、SSH 等应用层协议识别和 Banner 探测
- 支持多线程并发扫描
- 支持导出扫描结果至 Excel 文档

### 运行环境

本程序在 Ubuntu 20.04.6 LTS 系统上使用 Python 3.12.7 开发。

理论上 Python 程序具有较好的跨平台特性，由 PyInstaller 打包的二进制程序经测试可在 Windows 11 23H2、Ubuntu 20.04.6 LTS、macOS Sequoia 15.2 上正常运行，其他系统兼容性未进行测试。

若打包的二进制程序无法正常运行，可参照以下步骤配置 Python 运行环境，手动运行源代码：

1. 安装 Python 3.12
2. 安装依赖 `pip install -r requirements.txt`
3. 以管理员身份运行 `python main.py`

需要注意的是，由于操作系统限制，构造并发送网络底层数据包需要系统管理员权限，因此**必须使用管理员身份运行本程序**。

### 编译工具

Python 是解释型语言，无需编译。

使用 PyInstaller 可以将程序打包成便于分发的二进制文件，打包方法如下：

```bash
pyinstaller -D -w -n NaivePortScanner --optimize 2 main.py
```

### 程序文件列表

- `main.py`：主程序文件，实现图形界面
- `utils.py`：工具集文件，实现各类扫描函数和辅助函数
- `consts.py`：常量文件，定义程序中使用的各类常量，可按需修改

## 大模型交互过程

大模型交互使用了 VSCode IDE 中的 GitHub Copilot Chat 插件，该插件支持在提示词中附加当前工作区的代码文件，使用的模型是 GPT-4o。

![](https://notes.sjtu.edu.cn/uploads/upload_9568902564a80acdacbbfe5b888e64a3.png)

对于各类扫描算法的实现，直接查询 `scapy` 官方文档，构造相应的数据包，远比询问大模型快捷且准确。

对于图形界面的实现，使用 Tkinter 绘制窗体非常繁琐，有大量重复性工作，适合使用大模型辅助进行开发，只需描述图形界面窗体需求，大模型会生成相应的代码，具体交互过程如下：

![](https://notes.sjtu.edu.cn/uploads/upload_bfd2fa041642f91958251a6dc682e352.png)

第一次交互中，大模型使用了原生 Tkinter 实现了一个非常丑陋的图形界面，经过检索发现 `ttkbootstrap` 库可以对 Tkinter 进行美化，同时需要对图形界面需求进行更精确的描述，于是修改提示词进行第二次交互。

![](https://notes.sjtu.edu.cn/uploads/upload_c88e0003b56a7c14da0ad99933daef01.png)

此次大模型给出的回答已经比较令人满意，但是默认的窗体大小太小，且窗体放大后组件依然位于很小的一块固定区域，于是要求大模型进行修改，把默认窗体大小调大，同时禁止调整窗口大小。

![](https://notes.sjtu.edu.cn/uploads/upload_f49ae498a18789df851a3f7519492bdf.png)

这次大模型给出的回答只对了一半，窗体可随意调整大小的问题依然存在，于是改变要求，允许调整窗口大小，但是组件需要随窗口大小变化。

![](https://notes.sjtu.edu.cn/uploads/upload_933a8d9ddb08afb5ab7b28ebc9029819.png)

![](https://notes.sjtu.edu.cn/uploads/upload_2ab53ece844aacc9a206fc9831206b33.png)

这次大模型的调整是正确的。接下来，要求大模型补充放置两个按钮。

![](https://notes.sjtu.edu.cn/uploads/upload_2df20c87ecca7573d41509295611f185.png)

大模型给出了正确的结果，还绑定了对应的点击事件。继续优化扫描结果展示的部分，要求大模型使用树状结构展示扫描结果，在提示词中把层级关系描述清楚。

![](https://notes.sjtu.edu.cn/uploads/upload_716370ff361cd85c5456ffb7f29061dd.png)

大模型同样给出了可用的结果。至此，图形界面的设计和实现依靠大模型基本完成，后续在大模型给出的代码上进行了少量微调，使得界面交互逻辑更合理。

此外，在开发过程中还启用了 VSCode IDE 中的 GitHub Copilot 插件，在编写代码的过程中，GitHub Copilot 会自动根据当前光标处的代码上下文预测即将输入的内容，并以浅灰色字体显示，确认无误后按下 Tab 按键即可自动补全。

![](https://notes.sjtu.edu.cn/uploads/upload_31dcf3325480d9aeed16086744ccbe93.png)

## 实现的功能和函数说明

### 主机探测

#### ICMP Echo 探测

对应的函数位于 `utils.IcmpEchoScan`。

该函数接收参数 `ip`，使用 `scapy` 库提供的 `sr1` 函数构造并发送网络层数据包 `IP(dst=ip) / ICMP()`。

- 如果收到响应则认为 `ip` 对应的主机存活
- 否则认为主机离线

#### ARP 探测

对应的函数位于 `utils.ArpScan`。

该函数接收参数 `ip`，使用 `scapy` 库提供的 `sr1` 函数构造并发送网络层数据包 `ARP(pdst=ip)`。

- 如果收到响应则认为 `ip` 对应的主机存活
- 否则认为主机离线

### 端口扫描

#### TCP Connect 扫描

对应的函数位于 `utils.TcpConnectScan`。

该函数接收参数 `ip`、`port`，使用 `socket` 库提供的 `connect_ex` 函数尝试建立 TCP 连接。

- 若连接建立成功则认为端口开放
    - 进一步使用 `socket` 库提供的 `sendall` 和 `recv` 函数主动发送应用层报文，探测应用层协议的 Banner
- 否则认为端口关闭或受防火墙过滤

#### TCP SYN 扫描

对应的函数位于 `utils.TcpSynScan`。

该函数接收参数 `ip`、`port`，使用 `scapy` 库提供的 `sr1` 函数构造并发送网络层数据包 `IP(dst=ip) / TCP(sport=sport, dport=port, flags="S")`。

- 如果收到响应
    - 如果响应的 SYN 和 ACK 标志位置位则认为端口开放
    - 如果响应的 RST 标志位置位则认为端口关闭
- 否则认为端口受防火墙过滤

#### TCP FIN 扫描

对应的函数位于 `utils.TcpFinScan`。

该函数接收参数 `ip`、`port`，使用 `scapy` 库提供的 `sr1` 函数构造并发送网络层数据包 `IP(dst=ip) / TCP(sport=sport, dport=port, flags="F")`。

- 如果收到响应且响应的 RST 标志位置位则认为端口关闭
- 否则认为端口开放或受防火墙过滤

#### UDP 扫描

对应的函数位于 `utils.UdpScan`。

该函数接收参数 `ip`、`port`，使用 `scapy` 库提供的 `sr1` 函数构造并发送网络层数据包 `IP(dst=ip) / UDP(sport=sport, dport=port)`。

- 如果收到响应且响应是一个 UDP 数据包则认为端口开放
- 如果收到响应且响应是一个 ICMP 数据包
    - 如果响应是 ICMP 不可达错误（类型 3，代码 3）则认为端口关闭
    - 否则认为端口受防火墙过滤
- 否则认为端口开放或受防火墙过滤

### 多线程并发

对应的函数位于 `utils.ParallelHostScan` 和 `utils.ParallelPortScan`。

`utils.ParallelHostScan` 接收参数 `ips`、`callback`、`scan_type`，使用 `multiprocessing` 库初始化线程池，将每个 `ip` 应用到参数 `scan_type` 函数并使用参数 `callback` 作为回调函数，加入到线程池中。

`utils.ParallelPortScan` 接收参数 `ips`、`ports`、`callback`、`scan_type`，使用 `multiprocessing` 库初始化线程池，将每个 `(ip,port)` 元组应用到参数 `scan_type` 函数并使用参数 `callback` 作为回调函数，加入到线程池中。

### 扫描结果导出

对应的函数位于 `utils.SaveResults`。

该函数接收参数 `tree`（TreeView 控件实例），使用 `openpyxl` 库将扫描结果输出 Excel 文件，并保存至当前文件夹。

## 程序测试截图

选取上海交通大学学生宿舍有线网（新开网方式） `10.80.165.0/24` 网段进行测试（除 ARP 探测），端口扫描范围为 `21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017`。

### 主机探测

#### ICMP Echo 探测

![](https://notes.sjtu.edu.cn/uploads/upload_031eff9bf9b40e4cb6fbfe44cf3db036.png)

#### ARP 探测

由于 ARP 探测只适用于本地局域网，因此更换测试网段为宿舍本地局域网 `192.168.8.0/24`，扫描结果与路由器后台客户端列表一致。

![](https://notes.sjtu.edu.cn/uploads/upload_1f265297304c3bf09ebce85e4454ab95.png)

![](https://notes.sjtu.edu.cn/uploads/upload_b54b57f93429aaa6f0aa57d9ed1a5080.png)

### 端口扫描

#### TCP Connect 扫描

![](https://notes.sjtu.edu.cn/uploads/upload_20c4b37c386280929eb7286845aacfdb.png)

#### TCP SYN 扫描

![](https://notes.sjtu.edu.cn/uploads/upload_5abda4bea27bd67ac9a934ee2aa4fad7.png)

#### TCP FIN 扫描

![](https://notes.sjtu.edu.cn/uploads/upload_e6c21c684f0de860db37ec1f72d71899.png)

#### UDP 扫描

![](https://notes.sjtu.edu.cn/uploads/upload_3ed624d674376ce9c3593d7b323e2a59.png)

### 结果导出

![](https://notes.sjtu.edu.cn/uploads/upload_128f362de55b14aa3c6bf0b256955144.png)

![](https://notes.sjtu.edu.cn/uploads/upload_a06cf6b29ab51280edd215e799ce9111.png)

## 遇到的问题及解决方法

### 部分操作系统上开始扫描后程序崩溃

控制台日志显示 `Terminating app due to uncaught exception 'NSInternalInconsistencyException', reason: 'NSWindow should only be instantiated on the main thread!'`。

这是由于触发了部分操作系统的安全机制，这类操作系统不允许在非主线程更新 GUI，而本项目中每个扫描任务都运行在一个子线程中，扫描任务完成后的回调函数直接对窗体控件做出了修改（加入新的扫描结果），进而导致程序异常退出。解决方法是避免在回调函数中直接修改 GUI，而是采用生产者-消费者模型，扫描任务完成后仅将扫描结果加入队列，由主线程循环从队列中取出扫描结果，更新到 GUI 上。

## 体会与建议

- 实际应用了 TCP/IP 协议、Socket 编程、端口和服务的对应关系等计算机网络知识，加深了对这些概念的理解
- 学习了基于 Python 的跨平台应用程序开发和构建，学习了多线程异步编程
