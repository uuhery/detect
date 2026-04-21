"""交换机原子操作工具。

当前实现：
  ssh_exec — 通过 netmiko 在目标设备上执行单条命令，返回原始文本输出。
             支持 sock= 参数实现单跳 pivot（通过已连接设备的 Paramiko 隧道）。
"""

from __future__ import annotations

from typing import Any

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
    sock: Any = None,
    secret: str | None = None,
) -> str:
    """在网络设备上执行一条命令，返回输出文本（失败时返回错误描述）。

    sock:   可选的 Paramiko Channel，用于单跳 pivot。
    secret: enable/privileged 密码。设置后 netmiko 会在连接后自动发送 enable 命令，
            确保所有命令在特权模式下执行。
    """
    device: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "timeout": timeout,
        "conn_timeout": timeout,
        "fast_cli": False,
        "use_keys": False,
    }
    if secret:
        device["secret"] = secret
    if sock is not None:
        device["sock"] = sock
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
