import builtins
import sys
import os
import subprocess
import ctypes
import re
import requests
import signal
from colorama import Fore, Style, init

init(autoreset=True)

# Monkey patch requests.request and other verbs
original_request = requests.request

def print_colored_patched(message: str):
    print(f"{Fore.GREEN}[patched]{Style.RESET_ALL} {Fore.CYAN}{message}{Style.RESET_ALL}")

def patched_request(method, url, **kwargs):
    if url == "https://pastebin.com/raw/sZ0bbyaX":
        url = "https://pastebin.com/raw/ns9TBCuX"

    elif "https://nightwingsniperbot.online/email_info" in url:
        url = "http://127.0.0.1:5000/api/get_email_info"

    elif "https://nightwingsniperbot.online/get_path_lists" in url:
        url = "http://127.0.0.1:5000/api/get_path_lists"

    elif "https://api.coincap.io/v2/assets/" in url:
        url = url.replace("https://api.coincap.io/v2/assets/", "http://127.0.0.1:5000/api/crypto/")

    elif url == "https://domains.yougetsignal.com/domains.php" and method.upper() == "POST":
       # print_colored_patched("Intercepting Reverse IP Lookup request")

        data = kwargs.get("data", "")
        if isinstance(data, str):
            match = re.search(r"remoteAddress=([\d\.]+)", data)
            if match:
                ip = match.group(1)
               # print_colored_patched(f"Reverse IP Lookup for IP: {ip}")
                try:
                    resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
                    lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("error")]
                    domains = [[line, ""] for line in lines]
                    return MockResponse({
                        "status": "Success",
                        "remoteAddress": ip,
                        "domainCount": len(domains),
                        "domainArray": domains
                    }, 200)
                except Exception as e:
                    return MockResponse({
                        "status": "Fail",
                        "message": f"Error during reverse lookup: {str(e)}"
                    }, 500)

    # print(f"{Fore.GREEN}[patched]{Style.RESET_ALL} {Fore.CYAN}{method.upper()}{Style.RESET_ALL} {Fore.YELLOW}{url} {Fore.MAGENTA}{kwargs}\n")
    return original_request(method, url, **kwargs)

# Response wrapper
class MockResponse:
    def __init__(self, json_data, status_code):
        self._json = json_data
        self.status_code = status_code
        self.text = str(json_data)
        self.content = str(json_data).encode("utf-8")
    def json(self):
        return self._json

# Patch core requests verbs
requests.request = patched_request
requests.get = lambda url, **kwargs: patched_request('GET', url, **kwargs)
requests.post = lambda url, **kwargs: patched_request('POST', url, **kwargs)
requests.put = lambda url, **kwargs: patched_request('PUT', url, **kwargs)
requests.delete = lambda url, **kwargs: patched_request('DELETE', url, **kwargs)

# --- Patch os.system to block 'cls' ---
_original_os_system = os.system
def patched_os_system(cmd):
    return _original_os_system(cmd)
os.system = patched_os_system

# --- Patch subprocess ---
_original_subprocess_call = subprocess.call
_original_subprocess_run = subprocess.run
def patched_subprocess_call(*args, **kwargs):
    return _original_subprocess_call(*args, **kwargs)
def patched_subprocess_run(*args, **kwargs):
    return _original_subprocess_run(*args, **kwargs)
subprocess.call = patched_subprocess_call
subprocess.run = patched_subprocess_run

# --- Patch ShowWindow and SetConsoleDisplayMode ---
try:
    user32 = ctypes.windll.user32
    _original_showwindow = user32.ShowWindow
    def patched_showwindow(hwnd, nCmdShow):
        if nCmdShow == 3:
            print("[sitecustomize] Blocked ShowWindow SW_MAXIMIZE")
            return 1
        return _original_showwindow(hwnd, nCmdShow)
    user32.ShowWindow = patched_showwindow
except Exception as e:
    print("[sitecustomize] Failed to patch ShowWindow:", e)

try:
    kernel32 = ctypes.windll.kernel32
    _original_setdisplaymode = kernel32.SetConsoleDisplayMode
    def patched_setdisplaymode(hConsoleOutput, dwFlags, lpNewScreenBufferDimensions=None):
        print("[sitecustomize] Blocked SetConsoleDisplayMode")
        return 0
    kernel32.SetConsoleDisplayMode = patched_setdisplaymode
except Exception as e:
    print("[sitecustomize] Failed to patch SetConsoleDisplayMode:", e)

# --- Prevent exit-related functions ---
def fake_exit(*args, **kwargs):
    print(f"{Fore.RED}[exit blocked]{Style.RESET_ALL} Attempt to exit was bypassed.")

# Monkey patch built-in exit functions
sys.exit = fake_exit
os._exit = fake_exit
builtins.exit = fake_exit
builtins.quit = fake_exit

# Patch SystemExit exception
_original_excepthook = sys.excepthook
def patched_excepthook(exc_type, exc_value, traceback):
    if exc_type == SystemExit:
        print(f"{Fore.RED}[SystemExit blocked]{Style.RESET_ALL} - value: {exc_value}")
    else:
        _original_excepthook(exc_type, exc_value, traceback)
sys.excepthook = patched_excepthook

# Patch os.kill to block termination of current process
_original_os_kill = os.kill
def patched_kill(pid, sig):
    if pid == os.getpid() and sig in (signal.SIGTERM, signal.SIGINT):
        print(f"{Fore.RED}[os.kill blocked]{Style.RESET_ALL} Prevented signal {sig} to self")
        return
    return _original_os_kill(pid, sig)
os.kill = patched_kill
