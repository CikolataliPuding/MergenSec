"""MergenSec NVD API istemcisi ve CPE eşleştirme modülü.

Bu modül iki temel sorumluluğu yerine getirir:
1. Nmap çıktısındaki product/version bilgisini CPE 2.3 formatına dönüştürme.
2. NVD REST API v2 üzerinden asenkron CVE sorgulama.

NVD API Dokümantasyonu: https://nvd.nist.gov/developers/vulnerabilities
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

# NVD API v2 base URL
_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit: NVD, API key olmadan 5 istek/30 saniye izin veriyor
_REQUEST_DELAY_SECONDS = 6.0


@dataclass
class CVEItem:
    """Tek bir CVE kaydını temsil eder.

    Attributes:
        cve_id: CVE kimliği (örn. "CVE-2021-41773").
        description: CVE'nin İngilizce açıklaması.
        cvss_score: CVSS v3 base score (yoksa v2). None olabilir.
        severity: Önem derecesi (CRITICAL, HIGH, MEDIUM, LOW). None olabilir.
        published: Yayınlanma tarihi (ISO 8601 string).
    """

    cve_id: str
    description: str
    cvss_score: float | None
    severity: str | None
    published: str


@dataclass
class CVEQueryResult:
    """Bir CPE sorgusu için toplam CVE sonuçlarını tutar.

    Attributes:
        cpe_string: Sorguda kullanılan CPE 2.3 dizgesi.
        total_results: NVD'nin bildirdiği toplam eşleşme sayısı.
        cves: Döndürülen CVEItem listesi.
    """

    cpe_string: str
    total_results: int
    cves: list[CVEItem] = field(default_factory=list)


class CPEBuilder:
    """Nmap servis bilgisinden CPE 2.3 formatı oluşturur.

    CPE 2.3 formatı: cpe:2.3:part:vendor:product:version:*:*:*:*:*:*:*
    - part: 'a' (application), 'o' (os), 'h' (hardware)
    - vendor: genellikle product adından türetilir
    - product: küçük harf, boşluklar alt çizgi ile değiştirilir
    - version: sürüm numarası

    Örnek:
        >>> CPEBuilder.build("Apache httpd", "2.4.41")
        'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
    """

    # Bilinen vendor eşleştirmeleri: (product keyword → vendor, normalized_product)
    _VENDOR_MAP: dict[str, tuple[str, str]] = {
        "apache": ("apache", "http_server"),
        "nginx": ("nginx", "nginx"),
        "openssh": ("openbsd", "openssh"),
        "openssl": ("openssl", "openssl"),
        "mysql": ("mysql", "mysql"),
        "mariadb": ("mariadb", "mariadb"),
        "postgresql": ("postgresql", "postgresql"),
        "microsoft": ("microsoft", "iis"),
        "iis": ("microsoft", "iis"),
        "vsftpd": ("vsftpd_project", "vsftpd"),
        "proftpd": ("proftpd", "proftpd"),
        "postfix": ("postfix", "postfix"),
        "dovecot": ("dovecot", "dovecot"),
        "samba": ("samba", "samba"),
        "php": ("php", "php"),
        "python": ("python", "python"),
        "ruby": ("ruby-lang", "ruby"),
        "node": ("nodejs", "node.js"),
        "tomcat": ("apache", "tomcat"),
        "jenkins": ("jenkins", "jenkins"),
    }

    @classmethod
    def build(
        cls,
        product: str,
        version: str,
        part: str = "a",
    ) -> str:
        """Nmap product ve version bilgisinden CPE 2.3 dizgesi oluşturur.

        Args:
            product: Nmap'ten gelen ürün adı (örn. "Apache httpd", "OpenSSH").
            version: Servis sürümü (örn. "2.4.41", "8.9p1").
            part: CPE part değeri; 'a' uygulama, 'o' işletim sistemi,
                'h' donanım. Varsayılan: 'a'.

        Returns:
            Tam CPE 2.3 formatında dizge.
            Örnek: 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
        """
        vendor, normalized_product = cls._resolve_vendor_product(product)
        normalized_version = cls._normalize_version(version)

        cpe = (
            f"cpe:2.3:{part}:{vendor}:{normalized_product}"
            f":{normalized_version}:*:*:*:*:*:*:*"
        )
        logger.debug("CPE oluşturuldu: %s (kaynak: '%s' '%s')", cpe, product, version)
        return cpe

    @classmethod
    def _resolve_vendor_product(cls, product: str) -> tuple[str, str]:
        """Product adından vendor ve normalize edilmiş product adını çıkarır.

        Args:
            product: Ham ürün adı.

        Returns:
            (vendor, normalized_product) tuple'ı.
        """
        product_lower = product.lower()

        for keyword, (vendor, norm_product) in cls._VENDOR_MAP.items():
            if keyword in product_lower:
                return vendor, norm_product

        # Bilinmeyen ürün: ilk kelimeyi vendor, tamamını product olarak kullan
        parts = product_lower.split()
        vendor = cls._sanitize(parts[0]) if parts else "unknown"
        norm_product = cls._sanitize(product_lower)
        return vendor, norm_product

    @staticmethod
    def _sanitize(value: str) -> str:
        """CPE için geçersiz karakterleri temizler.

        Boşlukları alt çizgiye çevirir, alfanümerik olmayan karakterleri
        (nokta ve alt çizgi hariç) kaldırır.

        Args:
            value: Temizlenecek dizge.

        Returns:
            CPE uyumlu dizge.
        """
        value = value.lower().strip()
        value = re.sub(r"\s+", "_", value)
        value = re.sub(r"[^a-z0-9._\-]", "", value)
        return value or "unknown"

    @staticmethod
    def _normalize_version(version: str) -> str:
        """Sürüm dizgesini CPE uyumlu formata getirir.

        Boşlukları kaldırır, yalnızca rakam, nokta ve tire bırakır.
        Boş sürüm için '*' döndürür.

        Args:
            version: Ham sürüm dizgesi.

        Returns:
            Normalize edilmiş sürüm veya '*'.
        """
        if not version or not version.strip():
            return "*"
        normalized = re.sub(r"[^a-z0-9.\-]", "", version.lower().strip())
        return normalized or "*"


class NVDClient:
    """NVD REST API v2 üzerinden asenkron CVE sorgulama istemcisi.

    aiohttp kullanarak NVD'ye non-blocking HTTP istekleri gönderir.
    API key olmadan çalışır; ancak rate limit nedeniyle istekler arasında
    otomatik bekleme uygulanır.

    Typical usage example::

        async with NVDClient() as client:
            result = await client.get_cves_by_cpe(
                "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
            )
            for cve in result.cves:
                print(cve.cve_id, cve.cvss_score, cve.severity)

    Attributes:
        api_key: NVD API anahtarı (opsiyonel, rate limit'i artırır).
        results_per_page: Tek sorguda döndürülecek maksimum CVE sayısı.
        session: Dahili aiohttp.ClientSession nesnesi.
    """

    def __init__(
        self,
        api_key: str | None = None,
        results_per_page: int = 20,
    ) -> None:
        """NVDClient nesnesini başlatır.

        Args:
            api_key: NVD API anahtarı. None ise anonim mod (rate limit düşük).
            results_per_page: Sayfa başına maksimum sonuç. Varsayılan: 20.
        """
        self.api_key = api_key
        self.results_per_page = results_per_page
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "NVDClient":
        """Async context manager girişi: HTTP oturumu açar."""
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self._session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager çıkışı: HTTP oturumunu kapatır."""
        if self._session:
            await self._session.close()
            self._session = None

    def _get_session(self) -> aiohttp.ClientSession:
        """Aktif oturumu döndürür; yoksa hata fırlatır."""
        if self._session is None:
            raise RuntimeError(
                "NVDClient bir async context manager içinde kullanılmalıdır. "
                "Örnek: async with NVDClient() as client: ..."
            )
        return self._session

    async def get_cves_by_cpe(
        self,
        cpe_string: str,
        start_index: int = 0,
    ) -> CVEQueryResult:
        """Verilen CPE dizgesiyle eşleşen CVE'leri NVD'den sorgular.

        Args:
            cpe_string: CPE 2.3 formatında dizge.
                Örnek: 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
            start_index: Sayfalama için başlangıç indeksi. Varsayılan: 0.

        Returns:
            CVEQueryResult nesnesi; toplam sonuç sayısı ve CVEItem listesi.

        Raises:
            aiohttp.ClientError: HTTP isteği başarısız olursa.
            RuntimeError: API yanıtı beklenmedik formatta ise.
        """
        session = self._get_session()

        params: dict[str, Any] = {
            "cpeName": cpe_string,
            "resultsPerPage": self.results_per_page,
            "startIndex": start_index,
        }

        logger.info("NVD sorgusu başlatılıyor: %s", cpe_string)

        async with session.get(_NVD_API_BASE, params=params) as response:
            response.raise_for_status()
            data: dict = await response.json()

        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        cves = [
            self._parse_cve_item(vuln)
            for vuln in vulnerabilities
            if "cve" in vuln
        ]

        logger.info(
            "NVD sorgusu tamamlandı: %s | Toplam: %d | Döndürülen: %d",
            cpe_string,
            total,
            len(cves),
        )

        return CVEQueryResult(
            cpe_string=cpe_string,
            total_results=total,
            cves=cves,
        )

    async def get_cves_for_service(
        self,
        product: str,
        version: str,
    ) -> CVEQueryResult:
        """Nmap servis bilgisinden direkt CVE sorgusu yapar.

        CPEBuilder kullanarak CPE dizgesi oluşturur ve NVD'yi sorgular.
        Tek adımda Nmap çıktısından CVE listesine ulaşmak için kullanılır.

        Args:
            product: Nmap'ten gelen ürün adı (örn. "Apache httpd").
            version: Servis sürümü (örn. "2.4.41").

        Returns:
            CVEQueryResult nesnesi.
        """
        cpe = CPEBuilder.build(product, version)
        logger.debug("Servis için CPE: %s", cpe)
        return await self.get_cves_by_cpe(cpe)

    @staticmethod
    def _parse_cve_item(vuln: dict) -> CVEItem:
        """NVD API yanıtındaki tek bir vulnerability nesnesini ayrıştırır.

        Args:
            vuln: NVD API'den gelen vulnerability dict'i.

        Returns:
            CVEItem nesnesi.
        """
        cve_data = vuln["cve"]
        cve_id = cve_data.get("id", "UNKNOWN")
        published = cve_data.get("published", "")

        # Açıklama: İngilizce olanı tercih et
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS skoru: v3.1 > v3.0 > v2 önceliği
        cvss_score, severity = NVDClient._extract_cvss(cve_data)

        return CVEItem(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            published=published,
        )

    @staticmethod
    def _extract_cvss(cve_data: dict) -> tuple[float | None, str | None]:
        """CVE verisinden CVSS skoru ve önem derecesini çıkarır.

        v3.1, v3.0, v2.0 sırasıyla denenir.

        Args:
            cve_data: NVD API'den gelen CVE dict'i.

        Returns:
            (cvss_score, severity) tuple'ı; bulunamazsa (None, None).
        """
        metrics = cve_data.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
                return score, severity

        entries = metrics.get("cvssMetricV2", [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = entries[0].get("baseSeverity")
            return score, severity

        return None, None
