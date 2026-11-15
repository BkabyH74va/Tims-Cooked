#!/usr/bin/env python3
"""neofetch-like system info for a-Shell on iOS.
Pure Python - no shell calls (subprocess crashes Python in this context)."""
import os, platform, socket

uname = os.uname()
kernel_release = uname.release
machine = uname.machine

MODEL_NAMES = {"iPhone14,2": "iPhone 13 Pro", "iPhone18,1": "iPhone 17 Pro"}
model = MODEL_NAMES.get(machine, f"iPhone ({machine})")

OS_VERSION = "iOS 27.0 (24A5390f)"

def get_os():
    return OS_VERSION

def get_model():
    return model

def get_kernel():
    return f"Darwin {kernel_release}"

def get_uptime():
    return "?"

def get_shell():
    return "a-Shell 2.3.2 · Terminal"

def get_resolution():
    return "1170x2532 @3x"

def get_cpu():
    try:
        cores = os.cpu_count() or 6
    except Exception:
        cores = 6
    return f"Apple A15 · {cores} cores"

def get_gpu():
    return "Apple A15 GPU"

def get_memory():
    return "5.5 GiB total"

def get_disk():
    return "11.2 GiB free / 119.1 GiB"

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("198.51.100.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "?"

APPLE_LOGO = [
    "       .':",
    "    _ :'_",
    "  .'`_`-``.",
    " :________.-'",
    " :_______:",
    " :_______:",
    "  :_______:",
    "   `._.-._.'",
]

def main():
    C = "\033[1;36m"
    W = "\033[1;37m"
    G = "\033[1;32m"
    M = "\033[1;35m"
    reset = "\033[0m"

    user = os.environ.get("USER", "root")
    hostname = socket.gethostname()
    plain = f"{user}@{hostname}"
    title = f"{G}{user}{reset}@{M}{hostname}{reset}"
    underline = "-" * len(plain)

    lines = [
        ("OS", get_os()),
        ("Host", get_model()),
        ("Kernel", get_kernel()),
        ("Uptime", get_uptime()),
        ("Shell", get_shell()),
        ("Resolution", get_resolution()),
        ("CPU", get_cpu()),
        ("GPU", get_gpu()),
        ("Memory", get_memory()),
        ("Disk", get_disk()),
        ("IP", get_ip()),
    ]

    max_label = max(len(l) for l, _ in lines)
    print(f"\n{title}\n{underline}")
    for i, (label, value) in enumerate(lines):
        logo = APPLE_LOGO[i] if i < len(APPLE_LOGO) else ""
        pad = max(1, max_label - len(label) + 2)
        print(f"  {C}{logo}{reset}  {C}{label}{reset}{' ' * pad}: {W}{value}{reset}")
    print()


if __name__ == "__main__":
    main()
