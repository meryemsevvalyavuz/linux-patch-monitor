"""
Linux Patch Monitor - Surum Normalizasyon Yardimci Modulu
RPM (epoch:version-release) ve dpkg (version-release) formatlarindaki
surumleri karsilastirilabilir ortak bir forma cevirir.
"""

import re


def normalize_version(raw_version):
    """
    Girdi ornekleri:
      RPM:  "1:1.1.1k-1.el8"   -> epoch var
            "1.1.1k-1.el8"     -> epoch yok (none)
      dpkg: "1.1.1-1ubuntu2"   -> epoch hic kullanilmaz

    Cikti: (epoch:int, upstream_version:str, release:str) seklinde bir tuple.
    Boylece iki farkli formattaki surumleri ayni mantikla karsilastirabiliriz.
    """
    if not raw_version:
        return (0, "", "")

    version = raw_version.strip()

    # 1) Epoch ayikla (varsa basinda "N:" seklinde durur)
    epoch = 0
    if ":" in version:
        epoch_part, rest = version.split(":", 1)
        if epoch_part.isdigit():
            epoch = int(epoch_part)
            version = rest

    # 2) Release ayikla (son "-" isaretinden sonrasi release kabul edilir)
    if "-" in version:
        upstream, release = version.rsplit("-", 1)
    else:
        upstream, release = version, ""

    return (epoch, upstream, release)


def _split_alnum(s):
    """'1.1.1k' gibi bir stringi ['1','1','1','k'] gibi parcalara ayirir,
    boylece sayisal ve alfabetik kisimlar ayri ayri karsilastirilabilir."""
    return re.findall(r'\d+|[a-zA-Z]+', s)


def compare_versions(version_a, version_b):
    """
    Iki ham surum stringini karsilastirir.
    Donus degeri: -1 (a < b), 0 (esit), 1 (a > b)
    """
    epoch_a, upstream_a, release_a = normalize_version(version_a)
    epoch_b, upstream_b, release_b = normalize_version(version_b)

    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1

    parts_a = _split_alnum(upstream_a)
    parts_b = _split_alnum(upstream_b)

    for pa, pb in zip(parts_a, parts_b):
        if pa == pb:
            continue
        if pa.isdigit() and pb.isdigit():
            return -1 if int(pa) < int(pb) else 1
        return -1 if pa < pb else 1

    if len(parts_a) != len(parts_b):
        return -1 if len(parts_a) < len(parts_b) else 1

    return 0
