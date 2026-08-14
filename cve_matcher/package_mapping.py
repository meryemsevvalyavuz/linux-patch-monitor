"""
Linux Patch Monitor - Paket Adi Esleme Tablosu
Farkli dagitimlarda ayni yazilimin farkli isimlerle paketlenmesinden
kaynaklanan yanlis pozitifleri azaltmak icin kullanilir.

Anahtar: NVD'de arama yaparken kullandigimiz "urun adi" (TRACKED_PACKAGES icindeki isim)
Deger: bu urune karsilik gelen, kurulu paketlerde aranmasi GEREKEN gercek paket adi(lari)

Not: Bu bilincli olarak kucuk ve elle bakimi yapilan bir tablo - amac tum
olasi paket isimlerini kapsamak degil, siklikla karisan/yanlis pozitif
ureten ciftleri acikca cozmek.
"""

PACKAGE_NAME_MAP = {
    "mysql": ["mysql-server", "mysql-community-server"],
    "openssl": ["openssl", "libssl-dev", "libssl1.1", "libssl3"],
    "bash": ["bash"],
    "curl": ["curl", "libcurl4", "libcurl3-gnutls", "libcurl4-gnutls-dev"],
    "busybox": ["busybox"],
    "bind9": ["bind9", "bind9utils"],
}


def get_search_terms(product_name):
    """
    Verilen urun adi icin, kurulu paketlerde ARANACAK gercek paket adi
    listesini dondurur. Tabloda tanimli degilse, urun adinin kendisini
    tek elemanli liste olarak doner (eski davranisla geriye donuk uyumlu).
    """
    return PACKAGE_NAME_MAP.get(product_name, [product_name])

