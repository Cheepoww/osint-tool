"""
=============================================================================
  OSINT Tehdit İstihbaratı Toplama ve İşleme Aracı
  UTM Firewall Kara Liste Besleyici (Blacklist Feeder)
=============================================================================
  Desteklenen Kaynaklar: URLhaus, Feodo Tracker, PhishTank
  Çıktı Dosyaları  : xlog_threat_intel.txt | full_report.csv
  Kütüphaneler     : requests, pandas, re
=============================================================================
"""

import requests
import pandas as pd
import re
import time
import logging
from datetime import datetime

# ---------------------------------------------------------------------------
# LOGGING YAPILANDIRMASI
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("osint_tool.log", encoding="utf-8")
    ]
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SABITLER: Veri kaynakları ve çıktı dosya adları
# ---------------------------------------------------------------------------

# URLhaus: Zararlı URL/domain listesi (CSV formatında)
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Feodo Tracker: Aktif Botnet C2 IP adresleri (TXT formatında)
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# PhishTank: Doğrulanmış phishing URL'leri (CSV formatında)
# Not: PhishTank yüksek frekanslı isteklerde rate-limit uygulayabilir.
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

# Ücretsiz GeoIP API (api-key gerektirmez)
GEOIP_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode"

# Çıktı dosyaları
OUTPUT_XLOG   = "xlog_threat_intel.txt"
OUTPUT_REPORT = "full_report.csv"

# ip-api.com ücretsiz katman: 45 istek/dakika sınırı
GEOIP_RATE_LIMIT_DELAY = 1.4   # saniye cinsinden bekleme süresi

# GeoIP sorgusunun yapılacağı maksimum IP sayısı
# Bu sınırı aşan IP'ler için ülke alanı "Skipped (limit)" olarak işaretlenir.
GEOIP_MAX_QUERIES = 1000

# ---------------------------------------------------------------------------
# BÖLÜM 1: VERİ ÇEKME FONKSİYONLARI
# ---------------------------------------------------------------------------

def fetch_urlhaus() -> list[dict]:
    """
    URLhaus'tan son 30 güne ait zararlı URL kayıtlarını çeker.
    Yorum satırlarını (#) temizler, URL ve host alanlarını döndürür.

    Dönüş:
        [{"address": "http://...", "type": "url", "source": "URLhaus"}, ...]
    """
    log.info("URLhaus'tan veri çekiliyor...")
    records = []

    try:
        resp = requests.get(URLHAUS_URL, timeout=30)
        resp.raise_for_status()

        for line in resp.text.splitlines():
            # Yorum satırlarını ve boş satırları atla
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # CSV sütunlarını ayrıştır; URLhaus formatı: id,dateadded,url,url_status,...
            parts = line.split('","')
            if len(parts) < 3:
                continue

            # Ham tırnak işaretlerini temizle
            url = parts[2].strip('"').strip()
            if url.startswith("http"):
                records.append({
                    "address": url,
                    "type":    "url",
                    "source":  "URLhaus"
                })

        log.info(f"URLhaus: {len(records)} kayıt alındı.")

    except requests.exceptions.ConnectionError:
        log.error("URLhaus'a bağlanılamadı. İnternet bağlantısını kontrol edin.")
    except requests.exceptions.Timeout:
        log.error("URLhaus isteği zaman aşımına uğradı.")
    except requests.exceptions.HTTPError as e:
        log.error(f"URLhaus HTTP hatası: {e}")
    except Exception as e:
        log.error(f"URLhaus beklenmeyen hata: {e}")

    return records


def fetch_feodo() -> list[dict]:
    """
    Feodo Tracker'dan aktif Botnet C2 (Command & Control) IP adreslerini çeker.
    Sadece geçerli IPv4 adreslerini filtreler.

    Dönüş:
        [{"address": "1.2.3.4", "type": "ip", "source": "Feodo Tracker"}, ...]
    """
    log.info("Feodo Tracker'dan veri çekiliyor...")
    records = []

    # Geçerli IPv4 adresi için Regex deseni
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )

    try:
        resp = requests.get(FEODO_URL, timeout=30)
        resp.raise_for_status()

        for line in resp.text.splitlines():
            line = line.strip()
            # Yorum ve boş satırları atla
            if not line or line.startswith("#"):
                continue

            # Regex ile IPv4 doğrula
            if ip_pattern.match(line):
                records.append({
                    "address": line,
                    "type":    "ip",
                    "source":  "Feodo Tracker"
                })

        log.info(f"Feodo Tracker: {len(records)} IP adresi alındı.")

    except requests.exceptions.ConnectionError:
        log.error("Feodo Tracker'a bağlanılamadı.")
    except requests.exceptions.Timeout:
        log.error("Feodo Tracker isteği zaman aşımına uğradı.")
    except requests.exceptions.HTTPError as e:
        log.error(f"Feodo Tracker HTTP hatası: {e}")
    except Exception as e:
        log.error(f"Feodo Tracker beklenmeyen hata: {e}")

    return records


def fetch_phishtank() -> list[dict]:
    """
    PhishTank'tan doğrulanmış aktif phishing URL'lerini çeker.
    CSV dosyasındaki 'url' sütununu kullanır.

    Dönüş:
        [{"address": "http://...", "type": "url", "source": "PhishTank"}, ...]
    """
    log.info("PhishTank'tan veri çekiliyor...")
    records = []

    try:
        resp = requests.get(
            PHISHTANK_URL,
            timeout=60,
            headers={"User-Agent": "osint-threat-intel-tool/1.0"}
        )
        resp.raise_for_status()

        # pandas ile CSV oku; büyük dosya olabileceğinden sadece ilk 5000 satır al
        from io import StringIO
        df = pd.read_csv(StringIO(resp.text), usecols=["url"], nrows=5000)

        for url in df["url"].dropna():
            url = str(url).strip()
            if url.startswith("http"):
                records.append({
                    "address": url,
                    "type":    "url",
                    "source":  "PhishTank"
                })

        log.info(f"PhishTank: {len(records)} URL alındı.")

    except requests.exceptions.ConnectionError:
        log.error("PhishTank'a bağlanılamadı.")
    except requests.exceptions.Timeout:
        log.error("PhishTank isteği zaman aşımına uğradı.")
    except requests.exceptions.HTTPError as e:
        log.error(f"PhishTank HTTP hatası: {e}")
    except KeyError:
        log.error("PhishTank CSV formatı değişmiş olabilir; 'url' sütunu bulunamadı.")
    except Exception as e:
        log.error(f"PhishTank beklenmeyen hata: {e}")

    return records


# ---------------------------------------------------------------------------
# BÖLÜM 2: VERİ TEMİZLEME (PREPROCESSING)
# ---------------------------------------------------------------------------

def clean_and_deduplicate(records: list[dict]) -> pd.DataFrame:
    """
    Tüm kaynaklardan gelen ham kayıtları birleştirir,
    mükerrer (duplicate) girişleri temizler ve boş değerleri atar.

    Argümanlar:
        records: fetch_* fonksiyonlarından dönen tüm kayıtların listesi

    Dönüş:
        Temizlenmiş pandas DataFrame (sütunlar: address, type, source)
    """
    log.info("Veri temizleme ve tekilleştirme başlıyor...")

    if not records:
        log.warning("Temizlenecek kayıt bulunamadı.")
        return pd.DataFrame(columns=["address", "type", "source"])

    df = pd.DataFrame(records)

    # Başlangıç sayısı
    initial_count = len(df)

    # Boş ve NaN değerleri çıkar
    df.dropna(subset=["address"], inplace=True)
    df = df[df["address"].str.strip() != ""]

    # 'address' sütununa göre ilk kaydı koruyarak tekilleştir
    df.drop_duplicates(subset=["address"], keep="first", inplace=True)

    # İndeksi sıfırla
    df.reset_index(drop=True, inplace=True)

    removed = initial_count - len(df)
    log.info(f"Temizleme tamamlandı: {initial_count} → {len(df)} kayıt "
             f"({removed} mükerrer/boş silindi).")

    return df


def extract_ip_from_url(url: str) -> str | None:
    """
    Bir URL içindeki IPv4 adresini Regex ile ayıklar.
    Örnek: 'http://192.168.1.1/malware' → '192.168.1.1'
    URL'de domain varsa None döner (domain'ler GeoIP sorgusuna dahil değil).

    Argümanlar:
        url: Kontrol edilecek URL dizisi

    Dönüş:
        IPv4 adresi dizesi ya da None
    """
    ip_pattern = re.compile(
        r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    match = ip_pattern.search(url)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# BÖLÜM 3: GEOİP ENTEGRASYONu
# ---------------------------------------------------------------------------

def get_geoip_info(ip: str) -> dict:
    """
    ip-api.com ücretsiz API'si üzerinden bir IPv4 adresinin
    coğrafi konumunu (ülke adı ve ülke kodu) sorgular.

    Rate-limit: Dakikada 45 istek (ücretsiz katman).
    Bu nedenle her çağrı arasında GEOIP_RATE_LIMIT_DELAY kadar beklenir.

    Argümanlar:
        ip: Sorgulanacak IPv4 adresi ("1.2.3.4" formatında)

    Dönüş:
        {"country": "Germany", "country_code": "DE"}
        veya hata durumunda {"country": "Unknown", "country_code": "N/A"}
    """
    try:
        url  = GEOIP_API.format(ip=ip)
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "success":
            return {
                "country":      data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "N/A")
            }
        else:
            # Özel/yerel IP adresleri (RFC1918) vs.
            log.debug(f"GeoIP başarısız: {ip} → {data.get('message', 'unknown')}")
            return {"country": "Private/Reserved", "country_code": "N/A"}

    except requests.exceptions.ConnectionError:
        log.warning(f"GeoIP sorgusu için bağlantı hatası: {ip}")
    except requests.exceptions.Timeout:
        log.warning(f"GeoIP sorgusu zaman aşımı: {ip}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"GeoIP HTTP hatası ({ip}): {e}")
    except Exception as e:
        log.warning(f"GeoIP beklenmeyen hata ({ip}): {e}")

    return {"country": "Unknown", "country_code": "N/A"}


def enrich_with_geoip(df: pd.DataFrame, max_queries: int = GEOIP_MAX_QUERIES) -> pd.DataFrame:
    """
    DataFrame içindeki IP adreslerini GeoIP API ile zenginleştirir.
    URL kayıtlarında gömülü IP adresleri de Regex ile bulunarak sorgulanır.
    Domain tabanlı URL'ler için ülke alanları "N/A (Domain)" olarak işaretlenir.

    Sorgu limiti (max_queries) aşıldığında kalan IP'ler atlanır ve
    ülke alanı "Skipped (limit)" olarak kaydedilir; bu sayede program
    yüzlerce IP için gereksiz yere beklemez.

    Argümanlar:
        df         : Temizlenmiş tehdit kayıtları DataFrame'i
        max_queries: Sorgulanacak maksimum IP sayısı (varsayılan: GEOIP_MAX_QUERIES)

    Dönüş:
        'country' ve 'country_code' sütunları eklenmiş DataFrame
    """
    log.info(f"GeoIP zenginleştirmesi başlıyor (limit: ilk {max_queries} IP)...")

    countries      = []
    country_codes  = []

    # İşlenecek toplam IP sayısını hesapla (ilerleme için)
    ip_records  = df[df["type"] == "ip"]
    url_with_ip = df[df["type"] == "url"]["address"].apply(extract_ip_from_url).dropna()
    total_ips   = len(ip_records) + len(url_with_ip)

    # Gerçekte sorgulanacak sayı: toplam ile limit arasındaki küçük olan
    will_query  = min(total_ips, max_queries)
    log.info(f"Toplam {total_ips} IP bulundu → {will_query} tanesi sorgulanacak, "
             f"geri kalanı 'Skipped (limit)' olarak işaretlenecek.")

    processed = 0   # Başarılı API sorgusu sayacı

    for _, row in df.iterrows():
        ip_to_query = None

        if row["type"] == "ip":
            ip_to_query = row["address"]
        elif row["type"] == "url":
            # URL içinde gömülü IP var mı? (örn: http://45.33.32.156/evil)
            ip_to_query = extract_ip_from_url(row["address"])

        if ip_to_query:
            # Limit dolmuşsa API'ye istek atmadan atla
            if processed >= max_queries:
                countries.append("Skipped (limit)")
                country_codes.append("N/A")
                continue

            geo = get_geoip_info(ip_to_query)
            countries.append(geo["country"])
            country_codes.append(geo["country_code"])

            processed += 1
            if processed % 10 == 0:
                log.info(f"GeoIP ilerleme: {processed}/{will_query}")

            # Rate-limit aşımını önlemek için bekleme
            time.sleep(GEOIP_RATE_LIMIT_DELAY)
        else:
            # Domain tabanlı URL; GeoIP uygulanamaz
            countries.append("N/A (Domain)")
            country_codes.append("N/A")

    df["country"]      = countries
    df["country_code"] = country_codes

    skipped = total_ips - processed
    log.info(f"GeoIP tamamlandı: {processed} sorgulandı, {skipped} atlandı.")
    return df


# ---------------------------------------------------------------------------
# BÖLÜM 4: ÇIKTI OLUŞTURMA
# ---------------------------------------------------------------------------

def save_xlog_format(df: pd.DataFrame, filepath: str = OUTPUT_XLOG) -> None:
    """
    Xlog / UTM Firewall cihazlarının okuyabileceği sade TXT formatında
    kara liste dosyası oluşturur.
    Her satırda yalnızca bir adet IP veya URL adresi bulunur.

    Format örneği:
        # OSINT Threat Intel - 2025-06-15 08:30:00
        # Toplam: 1523 kayıt
        1.2.3.4
        http://malicious-site.com/payload

    Argümanlar:
        df      : İşlenmiş tehdit kayıtları DataFrame'i
        filepath: Hedef dosya yolu
    """
    log.info(f"Xlog formatında dosya kaydediliyor: {filepath}")

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            # Başlık yorumları
            f.write(f"# OSINT Threat Intel Kara Listesi\n")
            f.write(f"# Oluşturulma: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Toplam Kayıt: {len(df)}\n")
            f.write(f"# Kaynaklar: {', '.join(df['source'].unique())}\n")
            f.write("#" + "-" * 60 + "\n")

            for address in df["address"]:
                f.write(f"{address}\n")

        log.info(f"Xlog dosyası başarıyla oluşturuldu: {filepath} ({len(df)} satır)")

    except IOError as e:
        log.error(f"Xlog dosyası yazılamadı: {e}")


def save_full_report(df: pd.DataFrame, filepath: str = OUTPUT_REPORT) -> None:
    """
    Tüm ayrıntıları (adres, tür, kaynak, ülke bilgisi, zaman damgası)
    içeren kapsamlı bir CSV raporu oluşturur.
    Bu rapor analiz, denetim ve raporlama amaçlı kullanılabilir.

    CSV Sütunları:
        address       - IP veya URL adresi
        type          - Kayıt türü (ip / url)
        source        - Veri kaynağı (URLhaus, Feodo Tracker, PhishTank)
        country       - Ülke adı
        country_code  - ISO 3166-1 alpha-2 ülke kodu
        fetched_at    - Verinin çekildiği tarih-saat

    Argümanlar:
        df      : İşlenmiş tehdit kayıtları DataFrame'i (GeoIP ile zenginleştirilmiş)
        filepath: Hedef CSV dosya yolu
    """
    log.info(f"Tam rapor CSV olarak kaydediliyor: {filepath}")

    try:
        # Zaman damgası sütunu ekle
        df_out = df.copy()
        df_out["fetched_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sütun sıralamasını düzenle
        cols = ["address", "type", "source", "country", "country_code", "fetched_at"]
        # Var olmayan sütunları oluştur (GeoIP atlanmışsa)
        for col in cols:
            if col not in df_out.columns:
                df_out[col] = "N/A"

        df_out[cols].to_csv(filepath, index=False, encoding="utf-8-sig")
        log.info(f"Tam rapor başarıyla oluşturuldu: {filepath}")

    except IOError as e:
        log.error(f"CSV raporu yazılamadı: {e}")
    except Exception as e:
        log.error(f"CSV raporu beklenmeyen hata: {e}")


def print_summary(df: pd.DataFrame) -> None:
    """
    Konsola özet istatistikleri yazdırır:
    toplam kayıt sayısı, kaynaklara göre dağılım ve en çok görülen ülkeler.

    Argümanlar:
        df: GeoIP ile zenginleştirilmiş nihai DataFrame
    """
    print("\n" + "=" * 60)
    print("  OSINT TEHDİT İSTİHBARATI - ÖZET RAPORU")
    print("=" * 60)
    print(f"  Toplam Kayıt    : {len(df)}")
    print(f"  IP Adresi       : {len(df[df['type'] == 'ip'])}")
    print(f"  URL             : {len(df[df['type'] == 'url'])}")
    print()

    # Kaynak bazlı dağılım
    print("  [ Kaynak Dağılımı ]")
    for source, count in df["source"].value_counts().items():
        print(f"    {source:<20} : {count:>6} kayıt")
    print()

    # Ülke bazlı dağılım (sadece GeoIP başarılı IP'ler)
    if "country" in df.columns:
        ip_df = df[~df["country"].isin(["N/A (Domain)", "Unknown", "Private/Reserved", "N/A"])]
        if not ip_df.empty:
            print("  [ En Çok Tespit Edilen Ülkeler (IP bazlı) ]")
            for country, count in ip_df["country"].value_counts().head(10).items():
                print(f"    {country:<25} : {count:>5} IP")

    print("=" * 60)
    print(f"  Çıktı dosyaları:")
    print(f"    → {OUTPUT_XLOG}   (Xlog/UTM kara liste formatı)")
    print(f"    → {OUTPUT_REPORT}    (Detaylı analiz raporu)")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# ANA FONKSİYON: Tüm akışı koordine eder
# ---------------------------------------------------------------------------

def main():
    """
    Araç Ana Akışı:
        1. Tüm OSINT kaynaklarından veri çek
        2. Verileri birleştir, temizle ve tekilleştir
        3. GeoIP ile IP adreslerini zenginleştir
        4. Xlog formatında kara liste dosyası oluştur
        5. Detaylı CSV raporu kaydet
        6. Özet istatistikleri ekrana yazdır
    """
    log.info("=" * 60)
    log.info(" OSINT Tehdit İstihbaratı Aracı Başlatılıyor")
    log.info("=" * 60)

    # ------------------------------------------------------------------
    # ADIM 1: Veri Çekme
    # ------------------------------------------------------------------
    all_records = []

    all_records.extend(fetch_urlhaus())
    all_records.extend(fetch_feodo())
    all_records.extend(fetch_phishtank())

    if not all_records:
        log.error("Hiçbir kaynaktan veri alınamadı. Program sonlanıyor.")
        return

    # ------------------------------------------------------------------
    # ADIM 2: Temizleme ve Tekilleştirme
    # ------------------------------------------------------------------
    df_clean = clean_and_deduplicate(all_records)

    if df_clean.empty:
        log.error("Temizleme sonrası kayıt kalmadı. Program sonlanıyor.")
        return

    # ------------------------------------------------------------------
    # ADIM 3: GeoIP Zenginleştirme
    # NOT: Büyük veri setlerinde bu adım uzun sürebilir.
    #      Hızlı test için aşağıdaki satırı yorum yapabilirsiniz:
    #      df_enriched = df_clean.copy()
    # ------------------------------------------------------------------
    df_enriched = enrich_with_geoip(df_clean)

    # ------------------------------------------------------------------
    # ADIM 4 & 5: Dosyaları Kaydet
    # ------------------------------------------------------------------
    save_xlog_format(df_enriched)
    save_full_report(df_enriched)

    # ------------------------------------------------------------------
    # ADIM 6: Özet
    # ------------------------------------------------------------------
    print_summary(df_enriched)

    log.info("Tüm işlemler başarıyla tamamlandı.")


# ---------------------------------------------------------------------------
# PROGRAM GİRİŞ NOKTASI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
