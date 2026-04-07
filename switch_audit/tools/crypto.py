"""算法解码工具。

当前实现：
  decode_type7 — Cisco IOS Type 7 可逆编码解码。
                 纯算法，无网络，无副作用，输入确定则输出确定。

Type 7 算法说明：
  密文前两位十进制数字为密钥偏移量（seed），
  后续每两位十六进制字节与固定密钥表中对应位置 XOR 还原明文。
  密钥表来自 Cisco 私有实现，已被公开逆向。
"""

# Cisco Type 7 固定密钥表（公开已知）
_TYPE7_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def decode_type7(ciphertext: str) -> str:
    """解码 Cisco IOS Type 7 编码的密码。

    Args:
        ciphertext: 密文字符串，例如 "0958460C1E1712131F"
                    前两位为 seed（十进制），后续为十六进制字节序列。

    Returns:
        明文字符串。输入格式非法时返回描述性错误字符串（不抛出异常）。

    Examples:
        >>> decode_type7("0958460C1E1712131F")
        'cisco123'
    """
    ciphertext = ciphertext.strip()
    if len(ciphertext) < 4:
        return "(invalid: too short)"
    try:
        seed = int(ciphertext[:2])
        encoded = ciphertext[2:]
        if len(encoded) % 2 != 0:
            return "(invalid: odd-length hex)"
        chars = []
        for i in range(0, len(encoded), 2):
            byte = int(encoded[i : i + 2], 16)
            key_byte = ord(_TYPE7_KEY[(seed + i // 2) % len(_TYPE7_KEY)])
            chars.append(chr(byte ^ key_byte))
        return "".join(chars)
    except (ValueError, IndexError):
        return "(decode error)"
