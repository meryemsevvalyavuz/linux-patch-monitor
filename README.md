# Linux Patch Monitor ve CVE Eslestirme Sistemi

Kali Linux uzerinde calisan, kurulu paketleri izleyen, guncelleme durumunu
tespit eden, bilinen guvenlik aciklarini (CVE) NVD veritabani ile eslestiren
ve kritik aciklar icin Telegram uzerinden anlik bildirim gonderen bir sistem.

## Mimari

Agent -> API (FastAPI) -> PostgreSQL
CVE Matcher -> NVD -> PostgreSQL (cve_matches)
Panel (React) -> API -> PostgreSQL (okuma)
Notifier -> PostgreSQL -> Telegram -> Kullanici

## Bilesenler

- agent/ : Kurulu paketleri toplar, API'ye gonderir
- api/ : FastAPI backend, veritabani islemleri
- cve_matcher/ : NVD'den CVE ceker, kurulu paketlerle eslestirir
- panel/ : React tabanli yonetim paneli
- notifier/ : Kritik CVE'ler icin Telegram bildirimi gonderir
- run_all.sh : Agent + matcher + notifier'i sirayla calistirir

## Kurulum ve Calistirma

### 1. Veritabani

PostgreSQL kurulu ve calisir olmali. schema.sql dosyasi tablolari olusturur:

psql -U patchmon -d patchmon_db -h localhost -f schema.sql

### 2. API

cd api
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000

### 3. Panel

cd panel
npm run dev

Tarayicidan http://localhost:5173 adresinden erisilir.

### 4. Agent + CVE Matcher + Notifier

./run_all.sh

Bu script cron ile her gun saat 06:00'da otomatik calisacak sekilde
zamanlanmistir (bkz. crontab -l).

## Guncellemeler (2. asama)

- Agent artik RHEL/CentOS tabanli sistemleri de destekliyor (rpm -qa ile
  paket toplama, yum check-update ile eksik guncelleme tespiti). Sistemde
  hangi paket yoneticisinin bulundugu otomatik tespit edilir.
- Surum karsilastirmasi icin version_utils.py eklendi - RPM
  (epoch:version-release) ve dpkg (version-release) formatlarini ortak bir
  yapiya normallestirip karsilastirir.
- CVE eslestirmesi artik sabit 5 paketle sinirli degil; veritabanindaki
  tum benzersiz paketler taranir. Ayni paketin tekrar tekrar NVD'ye
  sorulmamasi icin artimli senkron uygulanir (nvd_sync_state tablosu,
  24 saatlik esik).
- NVD'den gelen surum araligi bilgisi kullanilarak kurulu surumun CVE'den
  gercekten etkilenip etkilenmedigi kontrol edilir.
- Paket adi eslestirmesi substring arama yerine tam eslesme ile yapiliyor.
  Substring aramanin alakasiz paketleri (ornegin python3 aramasinin
  yuzlerce alakasiz kutuphaneyi yakalamasi) yanlis pozitif olarak
  eslestirdigi tespit edilip duzeltildi. Farkli isimli paketler
  (mysql -> mysql-server gibi) icin package_mapping.py kullanilir.
- Panelde filo geneli dashboard (toplam/guncel/eksik guncellemeli/kritik
  CVE'li sunucu sayilari), renk kodlu sunucu listesi, ve sunucu bazinda
  sekmeli detay gorunumu (kurulu paketler / eksik guncellemeler / CVE
  kayitlari) eklendi.

## Bilinen Kisitlamalar

- Telegram bildirimi sadece Kritik seviyesindeki CVE'ler icin gonderiliyor.
- RHEL/CentOS destegi kod seviyesinde eklendi ancak gercek bir RHEL/CentOS
  sunucusunda henuz test edilmedi.
- Paket adi mapping tablosu (package_mapping.py) elle bakimi yapilan
  kucuk bir tablo, siklikla karisan ciftler icin genisletilebilir.

## Onemli Not

Paket kayitlari packages tablosunda upsert (guncelle/ekle) mantigiyla
tutulur. Bu davranis kesfedilip duzeltildi.
