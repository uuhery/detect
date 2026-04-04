"""
本地 Mock SSH 交换机服务 —— 无需 Docker，无需真实设备。

用法（在单独的终端里运行）：
    uv run python scripts/mock_switch.py

然后正常运行 audit：
    uv run python -m switch_audit.main --target 127.0.0.1

接受凭证：admin / admin（端口 2222）
"""

import socket
import threading
import time

import paramiko

# ── 假交换机的命令响应表 ────────────────────────────────────────────────────
RESPONSES: dict[str, str] = {
    # Cisco IOS 风格（同时收录带空格和带连字符的写法）
    "show version": (
        "Cisco IOS Software, Version 15.2(4)E8, RELEASE SOFTWARE (fc3)\n"
        "Technical Support: http://www.cisco.com/techsupport\n"
        "Model: WS-C2960X-48FPD-L\n"
        "ROM: Bootstrap program is C2960X boot loader\n"
        "Switch uptime is 42 days, 7 hours, 12 minutes\n"
        "System image file is 'flash:c2960x-universalk9-mz.152-4.E8.bin'\n"
        "Cisco WS-C2960X-48FPD-L (PowerPC) processor with 524288K bytes of memory.\n"
    ),
    "show ip arp": (
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
        "Internet  192.168.1.1             -   aabb.cc00.0100  ARPA   Vlan1\n"
        "Internet  192.168.1.100          12   0050.56aa.bbcc  ARPA   Vlan1\n"
        "Internet  192.168.1.101           5   0050.56aa.ddee  ARPA   Vlan1\n"
    ),
    "show interfaces": (
        "GigabitEthernet0/1 is up, line protocol is up\n"
        "  Hardware is Gigabit Ethernet, address is aabb.cc00.0101\n"
        "  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec\n"
        "  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX\n"
        "GigabitEthernet0/2 is administratively down, line protocol is down\n"
    ),
    "show running-config": (
        "Building configuration...\n"
        "!\n"
        "version 15.2\n"
        "hostname mock-switch\n"
        "!\n"
        "no mac-address-table aging-time\n"
        "mac-address-table static 0050.56aa.bbcc vlan 1 interface Gi0/1\n"
        "!\n"
        "vlan 1\n"
        "  name default\n"
        "!\n"
        "vlan 10\n"
        "  name MANAGEMENT\n"
        "!\n"
        "interface GigabitEthernet0/1\n"
        "  switchport mode access\n"
        "  switchport access vlan 1\n"
        "  spanning-tree portfast\n"
        "!\n"
        "interface Vlan1\n"
        "  ip address 192.168.1.1 255.255.255.0\n"
        "!\n"
        "line con 0\n"
        "line vty 0 4\n"
        "  login local\n"
        "  transport input ssh\n"
        "!\n"
        "end\n"
    ),
    "show vlan": (
        "VLAN Name                             Status    Ports\n"
        "---- -------------------------------- --------- -------------------------------\n"
        "1    default                          active    Gi0/1, Gi0/3, Gi0/4\n"
        "10   MANAGEMENT                       active    Gi0/2\n"
        "99   NATIVE                           active\n"
    ),
    "show spanning-tree": (
        "VLAN0001\n"
        "  Spanning tree enabled protocol rstp\n"
        "  Root ID    Priority    32769\n"
        "             Address     aabb.cc00.0100\n"
        "             This bridge is the root\n"
        "  Bridge ID  Priority    32769\n"
        "             Address     aabb.cc00.0100\n"
        "  Interface           Role Sts Cost      Prio.Nbr Type\n"
        "  Gi0/1               Desg FWD 4         128.1    P2p\n"
    ),
    # 带空格写法
    "show mac address-table": (
        "          Mac Address Table\n"
        "-------------------------------------------\n"
        "Vlan    Mac Address       Type        Ports\n"
        "----    -----------       --------    -----\n"
        "   1    0050.56aa.bbcc    DYNAMIC     Gi0/1\n"
        "   1    0050.56aa.ddee    DYNAMIC     Gi0/1\n"
        "   1    aabb.cc00.0100    STATIC      CPU\n"
    ),
    # Linux 风格（LLM 有时会尝试这些）
    "uname -a": "Linux mock-switch 5.15.0-91-generic x86_64 GNU/Linux\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\n",
    "cat /proc/version": (
        "Linux version 5.15.0-91-generic "
        "(gcc version 11.4.0) #101-Ubuntu SMP\n"
    ),
    "pwd": "/home/admin\n",
    "ls": "audit_log.txt  config.bak  startup-config\n",
    "help": (
        "Available commands: show version, show ip arp, show interfaces,\n"
        "show running-config, show vlan, show spanning-tree, show mac address-table\n"
    ),
}

# 带连字符的别名（LLM 经常会生成这种写法）
_ALIASES: dict[str, str] = {
    "show mac-address-table": "show mac address-table",
    "show ip-arp": "show ip arp",
    "show run": "show running-config",
}

_DEFAULT_RESPONSE = "% Unknown command. Type 'help' for available commands.\n"

# 生成临时 RSA 主机密钥（每次启动随机，不持久化）
_HOST_KEY = paramiko.RSAKey.generate(2048)


def _resolve_command(raw: str) -> str:
    """处理别名和管道（| include / | grep）。"""
    # 去掉管道部分，只用主命令查表（mock 不支持真正过滤，但能返回完整输出）
    base = raw.split("|")[0].strip()
    # 别名映射
    return _ALIASES.get(base, base)


class _SwitchServerInterface(paramiko.ServerInterface):
    """每个连接实例化一次，通过 Event 把 exec 请求传回主线程。"""

    def __init__(self) -> None:
        self.exec_event = threading.Event()
        self.exec_command: bytes = b""

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "admin" and password == "admin":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        # 只记录命令，由主线程负责发送响应（避免竞态）
        self.exec_command = command
        self.exec_event.set()
        return True


def _handle_client(conn: socket.socket, addr: tuple) -> None:
    print(f"[+] connection from {addr[0]}:{addr[1]}")
    server_iface = _SwitchServerInterface()
    transport = paramiko.Transport(conn)
    transport.add_server_key(_HOST_KEY)
    try:
        transport.start_server(server=server_iface)
    except paramiko.SSHException as exc:
        print(f"[-] SSH negotiation failed: {exc}")
        transport.close()
        return

    # 等待 channel 建立
    chan = transport.accept(timeout=20)
    if chan is None:
        print("[-] no channel opened")
        transport.close()
        return

    # 等待 exec 请求到达（由 check_channel_exec_request 触发 event）
    if not server_iface.exec_event.wait(timeout=10):
        print("[-] exec request timed out")
        chan.close()
        transport.close()
        return

    # 主线程统一发送响应，避免 channel 未就绪的竞态
    raw_cmd = server_iface.exec_command.decode("utf-8", errors="replace").strip()
    resolved = _resolve_command(raw_cmd)
    response = RESPONSES.get(resolved, _DEFAULT_RESPONSE)

    print(f"  [mock] raw={raw_cmd!r}")
    if resolved != raw_cmd:
        print(f"         resolved={resolved!r}")
    print(f"         -> {len(response)} bytes")

    chan.sendall(response.encode("utf-8"))
    chan.send_exit_status(0)

    # 给客户端充足时间读取数据后再关闭
    time.sleep(0.3)
    chan.close()
    time.sleep(0.1)
    transport.close()
    print(f"[-] connection from {addr[0]}:{addr[1]} closed")


def main() -> None:
    host, port = "127.0.0.1", 2222
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    sock.bind((host, port))
    sock.listen(10)
    print(f"Mock switch listening on {host}:{port}  (admin / admin)")
    print("Press Ctrl+C to stop.\n")
    try:
        while True:
            conn, addr = sock.accept()
            threading.Thread(
                target=_handle_client, args=(conn, addr), daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
