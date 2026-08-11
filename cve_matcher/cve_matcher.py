"""
Linux Patch Monitor - CVE Eslestirme Modulu
Belirlenen bir paket listesi icin NVD (National Vulnerability Database) API'sinden
CVE kayitlarini ceker, onbellege yazar, ve veritabanindaki kurulu paketlerle eslestirir.

NOT: Bu ilk versiyon versiyon araligi karsilastirmasi yapmiyor (ornegin OpenSSL 3.x'in
gercekten hangi CVE'lerden etkilendigini kontrol etmiyor). Amac, secilen paketler icin
NVD'de bilinen guncel CVE kayitlarini referans olarak sisteme dahil etmek. Versiyon
bazli hassas eslestirme, ileri asama gelistirme olarak birakildi.
"""

import time
import requests
import psycopg2

from config import DB_CONFIG

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Bu asamada takip edecegimiz paketler - populer ve NVD'de karsiligi net olanlar
TRACKED_PACKAGES = ["openssl", "bash", "curl", "busybox", "bind9"]

# Key'siz kullanimda NVD rate limit uyguluyor, istekler arasi bekleme suresi (saniye)
REQUEST_DELAY = 6


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


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
    """Veritabanindaki kurulu paketlerde bu isimde bir paket var mi bakar, varsa eslestirir"""
    cur.execute("""
        SELECT id FROM packages WHERE package_name ILIKE %s
    """, (f"%{product_name}%",))

    rows = cur.fetchall()
    match_count = 0

    for (package_id,) in rows:
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

    total_cves_fetched = 0
    total_matches = 0

    for package_name in TRACKED_PACKAGES:
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

        conn.commit()

        # NVD rate limit'e takilmamak icin istekler arasinda bekle
        time.sleep(REQUEST_DELAY)

    cur.close()
    conn.close()

    print(f"\n{'=' * 50}")
    print(f"Toplam onbellege alinan CVE: {total_cves_fetched}")
    print(f"Kurulu paketlerle eslesen kayit: {total_matches}")


if __name__ == "__main__":
    run()
