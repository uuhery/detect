"""交换机原子操作工具。

当前实现：
  ssh_exec — 通过 netmiko 在目标设备上执行单条命令，返回原始文本输出。
             netmiko 自动处理 Cisco invoke_shell、分页、提示符检测。

后续扩展：
  send_raw_packet — 发送原始数据包（需要 scapy）
  read_device_state — 读取并解析设备 MIB / REST API
"""

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


def ssh_exec(
    host: str,
    port: int,
    username: str,
    password: str,
    command: str,
    timeout: int = 30,
    device_type: str = "cisco_xe",
) -> str:
    """在网络设备上执行一条命令，返回输出文本（失败时返回错误描述）。

    device_type 遵循 netmiko 命名约定：
      cisco_xe   — IOS XE（Catalyst 8000、CSR1000V 等）
      cisco_ios  — 经典 IOS
      cisco_nxos — NX-OS
    """
    device = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "timeout": timeout,
        "conn_timeout": timeout,
        "fast_cli": False,  # 关闭快速模式，提高稳定性
        "use_keys": False,  # 空密码时禁止自动回退到密钥认证
    }
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command(command)
        return output.strip() if output.strip() else "(empty output)"
    except NetmikoAuthenticationException:
        return "[ssh_error] Authentication failed — check username/password"
    except NetmikoTimeoutException:
        return f"[ssh_error] Connection timed out after {timeout}s"
    except Exception as exc:
        return f"[ssh_error] {exc}"
