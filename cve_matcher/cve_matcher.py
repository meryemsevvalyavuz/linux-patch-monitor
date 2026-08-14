"""
Linux Patch Monitor - CVE Eslestirme Modulu
Veritabanindaki kurulu paketlerin tamami icin NVD (National Vulnerability Database)
API'sinden CVE kayitlarini ceker, onbellege yazar, surum araligina gore veritabanindaki
kurulu paketlerle eslestirir. Ayni paketi her calistirmada tekrar sorgulamamak icin
artimli (incremental) senkron uygular.
"""

import time
import requests
import psycopg2

from config import DB_CONFIG
from package_mapping import get_search_terms
from version_utils import compare_versions

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Kac saatte bir ayni paketi tekrar NVD'de sorgulayabiliriz (incremental sync icin)
SYNC_INTERVAL_HOURS = 24

# Key'siz kullanimda NVD rate limit uyguluyor, istekler arasi bekleme suresi (saniye)
REQUEST_DELAY = 6


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def get_tracked_packages(cur):
    """Veritabanindaki kurulu paketlerin benzersiz isim listesini doner -
    artik sabit 5 paket yerine gercekte kurulu olan her sey taranir."""
    cur.execute("SELECT DISTINCT package_name FROM packages ORDER BY package_name")
    return [row[0] for row in cur.fetchall()]


def needs_sync(cur, product_name):
    """Bu paket daha once hic senkronize edilmemis mi, ya da SYNC_INTERVAL_HOURS'tan
    daha eski mi senkronize edilmis - ikisinde de True doner (yeniden sorgulanmali)."""
    cur.execute("""
        SELECT last_synced_at FROM nvd_sync_state WHERE product_name = %s
    """, (product_name,))
    row = cur.fetchone()

    if row is None or row[0] is None:
        return True

    last_synced_at = row[0]
    cur.execute("""
        SELECT NOW() - %s > INTERVAL '%s hours'
    """, (last_synced_at, SYNC_INTERVAL_HOURS))
    return cur.fetchone()[0]


def mark_synced(cur, product_name):
    cur.execute("""
        INSERT INTO nvd_sync_state (product_name, last_synced_at)
        VALUES (%s, NOW())
        ON CONFLICT (product_name)
        DO UPDATE SET last_synced_at = NOW()
    """, (product_name,))


def severity_from_score(score):
    if score is None:
        return "Bilinmiyor"
    if score >= 9.0:
        return "Kritik"
    if score >= 7.0:
        return "Yuksek"
    if score >= 4.0:
        return "Orta"
    return "Dusuk"


def search_nvd(keyword, results_per_page=10):
    """NVD API'sinden keyword'e gore CVE arar, en fazla results_per_page kayit doner"""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    resp = requests.get(NVD_API_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data.get("vulnerabilities", [])


def extract_version_range(vuln_entry):
    """NVD kaydinin configurations alanindan surum araligi sinirlarini cikarir.
    Bulamazsa None doner (yani sinir bilgisi yok, referans olarak kabul edilir)."""
    cve = vuln_entry["cve"]

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                range_info = {}
                if "versionStartIncluding" in cpe_match:
                    range_info["start_including"] = cpe_match["versionStartIncluding"]
                if "versionStartExcluding" in cpe_match:
                    range_info["start_excluding"] = cpe_match["versionStartExcluding"]
                if "versionEndIncluding" in cpe_match:
                    range_info["end_including"] = cpe_match["versionEndIncluding"]
                if "versionEndExcluding" in cpe_match:
                    range_info["end_excluding"] = cpe_match["versionEndExcluding"]

                if range_info:
                    return range_info

    return None


def is_version_affected(installed_version, version_range):
    """Kurulu surumun, NVD'den gelen surum araligina girip girmedigini kontrol eder.
    version_range None ise (NVD sinir vermemis) -> etkilenmis SAY (eski, guvenli davranis).
    """
    if version_range is None:
        return True

    if "start_including" in version_range:
        if compare_versions(installed_version, version_range["start_including"]) < 0:
            return False
    if "start_excluding" in version_range:
        if compare_versions(installed_version, version_range["start_excluding"]) <= 0:
            return False
    if "end_including" in version_range:
        if compare_versions(installed_version, version_range["end_including"]) > 0:
            return False
    if "end_excluding" in version_range:
        if compare_versions(installed_version, version_range["end_excluding"]) >= 0:
            return False

    return True


def extract_cve_info(vuln_entry):
    """NVD'nin dondurdugu tek bir kaydi bizim kullanacagimiz basit forma cevirir"""
    cve = vuln_entry["cve"]
    cve_id = cve["id"]

    description = ""
    for desc in cve.get("descriptions", []):
        if desc["lang"] == "en":
            description = desc["value"]
            break

    # CVSS v3 varsa onu tercih ediyoruz, yoksa v2'ye dusuyoruz
    cvss_score = None
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity_from_score(cvss_score),
        "version_range": extract_version_range(vuln_entry),
    }


def save_to_cache(cur, cve_info, product_name):
    cur.execute("""
        INSERT INTO nvd_cve_cache (cve_id, description, cvss_score, severity, affected_product)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (cve_id)
        DO UPDATE SET
            description = EXCLUDED.description,
            cvss_score = EXCLUDED.cvss_score,
            severity = EXCLUDED.severity,
            affected_product = EXCLUDED.affected_product,
            synced_at = NOW()
    """, (cve_info["cve_id"], cve_info["description"], cve_info["cvss_score"],
          cve_info["severity"], product_name))


def match_to_installed_packages(cur, cve_info, product_name):
    """Veritabanindaki kurulu paketlerde bu urune karsilik gelen gercek
    paket adlarini arar (package_mapping uzerinden), surum araligina
    giriyorsa eslestirir."""
    search_terms = get_search_terms(product_name)

    matched_packages = {}  # package_id -> installed_version
    for term in search_terms:
        # ILIKE '%term%' yerine TAM ESLESME kullaniyoruz - substring arama
        # "python3" gibi genel bir terimin, icinde "python3" gecen yuzlerce
        # alakasiz pakete (python3-aiocmd, libpython3-dev vb.) yanlis pozitif
        # olarak baglanmasini onler. Farkli paket adlariyla eslesmesi gereken
        # durumlar (mysql -> mysql-server) icin package_mapping.py kullanilir.
        cur.execute("""
            SELECT id, installed_version FROM packages WHERE package_name = %s
        """, (term,))
        for package_id, installed_version in cur.fetchall():
            matched_packages[package_id] = installed_version

    match_count = 0

    for package_id, installed_version in matched_packages.items():
        if not is_version_affected(installed_version, cve_info["version_range"]):
            continue

        # ayni cve zaten bu paket icin kayitli mi, tekrar eklememek icin kontrol
        cur.execute("""
            SELECT id FROM cve_matches WHERE package_id = %s AND cve_id = %s
        """, (package_id, cve_info["cve_id"]))

        if cur.fetchone() is None:
            cur.execute("""
                INSERT INTO cve_matches (package_id, cve_id, description, cvss_score, severity)
                VALUES (%s, %s, %s, %s, %s)
            """, (package_id, cve_info["cve_id"], cve_info["description"],
                  cve_info["cvss_score"], cve_info["severity"]))
            match_count += 1

    return match_count


def run():
    conn = get_connection()
    cur = conn.cursor()

    tracked_packages = get_tracked_packages(cur)
    print(f"Veritabaninda {len(tracked_packages)} benzersiz paket bulundu.")

    total_cves_fetched = 0
    total_matches = 0
    skipped_count = 0

    for package_name in tracked_packages:
        if not needs_sync(cur, package_name):
            skipped_count += 1
            continue

        print(f"\n[{package_name}] NVD'den CVE cekiliyor...")

        try:
            results = search_nvd(package_name, results_per_page=10)
        except requests.exceptions.RequestException as e:
            print(f"  HATA: NVD sorgusu basarisiz -> {e}")
            time.sleep(REQUEST_DELAY)
            continue

        print(f"  {len(results)} CVE kaydi alindi")

        for entry in results:
            cve_info = extract_cve_info(entry)
            save_to_cache(cur, cve_info, package_name)
            matches = match_to_installed_packages(cur, cve_info, package_name)
            total_matches += matches
            total_cves_fetched += 1

        mark_synced(cur, package_name)
        conn.commit()

        # NVD rate limit'e takilmamak icin istekler arasinda bekle
        time.sleep(REQUEST_DELAY)

    cur.close()
    conn.close()

    print(f"\n{'=' * 50}")
    print(f"Zaten guncel oldugu icin atlanan paket: {skipped_count}")
    print(f"Toplam onbellege alinan CVE: {total_cves_fetched}")
    print(f"Kurulu paketlerle eslesen kayit: {total_matches}")


if __name__ == "__main__":
    run()
