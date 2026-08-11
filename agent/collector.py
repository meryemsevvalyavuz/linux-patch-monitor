"""
Linux Patch Monitor - Agent
Bu script sunucudaki kurulu paketleri toplar, guncelleme durumunu kontrol eder,
ve sonucu Patch Monitor API'sine gonderir.
Simdilik sadece Debian/Ubuntu tabanli sistemler icin (dpkg/apt).
"""

import subprocess
import socket
from datetime import datetime

import requests

API_URL = "http://localhost:8000"


def get_hostname():
    return socket.gethostname()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_os_info():
    os_name = "unknown"
    os_version = "unknown"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split("=")[1].strip().strip('"')
                if line.startswith("VERSION_ID="):
                    os_version = line.split("=")[1].strip().strip('"')
    except FileNotFoundError:
        pass
    return os_name, os_version


def get_installed_packages():
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        capture_output=True, text=True
    )

    packages = {}
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) == 2:
            name, version = parts
            packages[name] = version

    return packages


def get_upgradable_packages():
    result = subprocess.run(
        ["apt", "list", "--upgradable"],
        capture_output=True, text=True
    )

    upgradable = {}
    for line in result.stdout.strip().split("\n"):
        if "/" not in line or line.startswith("Listing"):
            continue
        try:
            name = line.split("/")[0]
            new_version = line.split(" ")[1]
            upgradable[name] = new_version
        except IndexError:
            continue

    return upgradable


def register_server(hostname):
    os_name, os_version = get_os_info()
    payload = {
        "hostname": hostname,
        "ip_address": get_local_ip(),
        "os_name": os_name,
        "os_version": os_version,
    }
    resp = requests.post(f"{API_URL}/servers/register", json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def send_packages(hostname, installed, upgradable):
    packages = []
    for name, version in installed.items():
        packages.append({
            "package_name": name,
            "installed_version": version,
            "available_version": upgradable.get(name),
        })

    resp = requests.post(
        f"{API_URL}/servers/{hostname}/packages",
        json={"packages": packages},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def collect():
    hostname = get_hostname()
    installed = get_installed_packages()
    upgradable = get_upgradable_packages()

    print(f"Sunucu: {hostname}")
    print(f"Toplama zamani: {datetime.now()}")
    print(f"Toplam kurulu paket: {len(installed)}")
    print(f"Guncellenebilir paket: {len(upgradable)}")
    print("-" * 50)

    try:
        reg_result = register_server(hostname)
        print(f"Sunucu kaydi tamam, server_id={reg_result['server_id']}")

        pkg_result = send_packages(hostname, installed, upgradable)
        print(f"Paketler API'ye gonderildi: {pkg_result['packages_saved']} adet")

    except requests.exceptions.ConnectionError:
        print("HATA: API'ye baglanilamadi. API calisiyor mu kontrol et (uvicorn ayakta mi).")
    except requests.exceptions.HTTPError as e:
        print(f"HATA: API bir hata dondu -> {e}")


if __name__ == "__main__":
    collect()
