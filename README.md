# Linux Patch Monitor ve CVE Eslestirme Sistemi

Kali Linux uzerinde calisan, kurulu paketleri izleyen, guncelleme durumunu
tespit eden, bilinen guvenlik aciklarini (CVE) NVD veritabani ile eslestiren
ve kritik aciklar icin Telegram uzerinden anlik bildirim gonderen bir sistem.

## Mimari
```
Agent -> API (FastAPI) -> PostgreSQL
CVE Matcher -> NVD -> PostgreSQL (cve_matches)
Panel (React) -> API -> PostgreSQL (okuma)
Notifier -> PostgreSQL -> Telegram -> Kullanici
```


## Bilesenler

| Klasor         | Gorev                                              |
|----------------|-----------------------------------------------------|
| `agent/`       | Kurulu paketleri toplar, API'ye gonderir            |
| `api/`         | FastAPI backend, veritabani islemleri               |
| `cve_matcher/` | NVD'den CVE ceker, kurulu paketlerle eslestirir     |
| `panel/`       | React tabanli yonetim paneli                        |
| `notifier/`    | Kritik CVE'ler icin Telegram bildirimi gonderir     |
| `run_all.sh`   | Agent + matcher + notifier'i sirayla calistirir     |

## Kurulum ve Calistirma

### 1. Veritabani
PostgreSQL kurulu ve calisir olmali. `schema.sql` dosyasi tablolari olusturur:
```bash
psql -U patchmon -d patchmon_db -h localhost -f schema.sql
```

### 2. API (surekli calisir halde kalmali)
```bash
cd api
source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Panel (gelistirme sunucusu)
```bash
cd panel
npm run dev
```
Tarayicidan `http://localhost:5173` adresinden erisilir.

### 4. Agent + CVE Matcher + Notifier (tek seferlik veya cron ile)
```bash
./run_all.sh
```

Bu script `cron` ile her gun saat 06:00'da otomatik calisacak sekilde
zamanlanmistir (bkz. `crontab -l`).

## Bilinen Kisitlamalar

- CVE eslestirmesi su an sadece 5 populer paket icin yapiliyor
  (openssl, bash, curl, busybox, bind9) - tum paketler icin NVD'nin
  CPE (urun tanimlayici) eslestirmesi otomatik ve guvenilir yapilamadigindan
  kapsam bilinçli olarak sinirlandirildi.
- Versiyon araligi karsilastirmasi yapilmiyor; NVD'de bulunan CVE kayitlari
  referans olarak listeleniyor, kurulu surumun o CVE'den etkilenip
  etkilenmedigi ayrica dogrulanmiyor.
- Su an sadece Debian/Ubuntu tabanli sistemler destekleniyor (dpkg/apt).
- Telegram bildirimi sadece "Kritik" seviyesindeki CVE'ler icin gonderiliyor.

## Onemli Not

Paket kayitlari `packages` tablosunda upsert (guncelle/ekle) mantigiyla
tutulur - agent her calistiginda tum kayitlarin silinip yeniden
olusturulmasi, bagli CVE eslestirmelerinin kaybolmasina ve mukerrer
Telegram bildirimlerine yol acmisti. Bu davranis kesfedilip duzeltildi.
