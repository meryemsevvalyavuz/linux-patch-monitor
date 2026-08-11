"""
Linux Patch Monitor - Telegram Bildirim Modulu
Veritabanindaki kritik CVE eslesmelerini kontrol eder, henuz bildirimi
gonderilmemis olanlar icin Telegram'a mesaj atar ve kaydi isaretler.
"""

import requests
import psycopg2
from psycopg2.extras import RealDictCursor

from config import DB_CONFIG, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

# Hangi seviyedeki CVE'ler icin bildirim atalim - simdilik sadece Kritik olanlar
# Yuksek de eklenebilir ama o zaman bildirim sayisi hizla artar, kapsami dar tuttum
NOTIFY_SEVERITIES = ["Kritik"]


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


def send_telegram_message(text):
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }
    resp = requests.post(TELEGRAM_API_URL, data=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def format_message(row):
    return (
        f"<b>Kritik Guvenlik Acigi Tespit Edildi</b>\n\n"
        f"Sunucu: {row['hostname']}\n"
        f"Paket: {row['package_name']} ({row['installed_version']})\n"
        f"CVE: {row['cve_id']}\n"
        f"CVSS Puani: {row['cvss_score']}\n\n"
        f"{row['description'][:200]}..."
    )


def get_unnotified_critical_cves(cur):
    placeholders = ",".join(["%s"] * len(NOTIFY_SEVERITIES))
    cur.execute(f"""
        SELECT cm.id, cm.cve_id, cm.cvss_score, cm.severity, cm.description,
               p.package_name, p.installed_version, s.hostname
        FROM cve_matches cm
        JOIN packages p ON cm.package_id = p.id
        JOIN servers s ON p.server_id = s.id
        WHERE cm.severity IN ({placeholders}) AND cm.notified = FALSE
        ORDER BY cm.cvss_score DESC
    """, NOTIFY_SEVERITIES)
    return cur.fetchall()


def mark_as_notified(cur, match_id):
    cur.execute("UPDATE cve_matches SET notified = TRUE WHERE id = %s", (match_id,))


def run():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    rows = get_unnotified_critical_cves(cur)

    if not rows:
        print("Bildirim bekleyen kritik CVE yok.")
        cur.close()
        conn.close()
        return

    print(f"{len(rows)} adet bildirilmemis kritik CVE bulundu, gonderiliyor...")

    sent_count = 0
    for row in rows:
        try:
            message = format_message(row)
            send_telegram_message(message)
            mark_as_notified(cur, row["id"])
            conn.commit()
            sent_count += 1
            print(f"  Gonderildi: {row['cve_id']} ({row['package_name']})")
        except requests.exceptions.RequestException as e:
            print(f"  HATA: {row['cve_id']} gonderilemedi -> {e}")

    cur.close()
    conn.close()

    print(f"\nToplam gonderilen bildirim: {sent_count}")


if __name__ == "__main__":
    run()
