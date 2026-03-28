"""MergenSec asenkron ağ tarama motoru.

Bu modül, Nmap binary'sini doğrudan asyncio alt süreçleri aracılığıyla
çağıran, event loop'u bloklamayan yüksek performanslı bir tarama motoru
sağlar. Birden fazla hedefin eş zamanlı taranması için asyncio.gather
ve asyncio.Queue ile uyumlu şekilde tasarlanmıştır.
"""

import asyncio
import ipaddress
import logging
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Final

logger = logging.getLogger(__name__)

_NMAP_TIMEOUT_SECONDS: Final[int] = 300
_NMAP_FLAGS: Final[list[str]] = ["-sV", "--script=banner", "-oX", "-"]


@dataclass(frozen=True)
class PortInfo:
    """Tek bir açık port hakkındaki yapılandırılmış veri.

    Attributes:
        portid: Port numarası (örn. 80, 443).
        service_name: Servis adı (örn. "http", "ssh").
        product: Servis yazılımının ürün adı (örn. "Apache httpd").
        version: Servis yazılımının sürüm numarası (örn. "2.4.51").
    """

    portid: int
    service_name: str
    product: str
    version: str


@dataclass
class ScanResult:
    """Bir hedef için tam tarama sonucunu temsil eder.

    Attributes:
        target_ip: Taranan hedefin IP adresi veya hostname'i.
        status: Hedefin ağ durumu; "up" veya "down".
        open_ports: Açık portlara ait PortInfo nesnelerinin listesi.
    """

    target_ip: str
    status: str
    open_ports: list[PortInfo] = field(default_factory=list)

    def to_dict(self) -> dict:
        """ScanResult nesnesini JSON-serileştirilebilir bir sözlüğe dönüştürür.

        Returns:
            target_ip, status ve open_ports anahtarlarını içeren sözlük.
        """
        return {
            "target_ip": self.target_ip,
            "status": self.status,
            "open_ports": [
                {
                    "portid": p.portid,
                    "service_name": p.service_name,
                    "product": p.product,
                    "version": p.version,
                }
                for p in self.open_ports
            ],
        }


class NmapNotFoundError(RuntimeError):
    """Nmap binary'si sistemde bulunamadığında fırlatılır."""


class ScanTimeoutError(TimeoutError):
    """Nmap taraması izin verilen süreyi aştığında fırlatılır."""


class InvalidTargetError(ValueError):
    """Hedef IP adresi veya hostname geçersiz olduğunda fırlatılır."""


class AsyncScanner:
    """Asyncio tabanlı, yüksek performanslı asenkron Nmap tarama motoru.

    Nmap'i doğrudan bir alt süreç olarak çalıştırır; python-nmap gibi
    senkron kütüphaneler kullanmaz. Bu sayede event loop bloklanmadan
    birden fazla hedef eş zamanlı olarak taranabilir.

    Typical usage example::

        scanner = AsyncScanner()

        # Tek hedef taraması
        result = await scanner.scan_target("192.168.1.1")
        print(result)

        # Çoklu eş zamanlı tarama
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        results = await asyncio.gather(
            *[scanner.scan_target(t) for t in targets]
        )

    Attributes:
        nmap_path: Nmap binary'sinin tam yolu.
        timeout: Tek bir tarama için maksimum bekleme süresi (saniye).
        extra_flags: Varsayılan flaglara ek olarak Nmap'e geçirilecek argümanlar.
    """

    def __init__(
        self,
        nmap_path: str | None = None,
        timeout: int = _NMAP_TIMEOUT_SECONDS,
        extra_flags: list[str] | None = None,
    ) -> None:
        """AsyncScanner nesnesini başlatır ve Nmap binary'sini doğrular.

        Args:
            nmap_path: Nmap binary'sinin tam dosya yolu. None ise PATH
                üzerinden otomatik olarak tespit edilir.
            timeout: Bir taramanın zaman aşımına uğramadan önce
                bekleneceği maksimum süre (saniye). Varsayılan: 300.
            extra_flags: Temel Nmap argümanlarına eklenecek ek bayraklar.
                Örneğin: ["--max-retries", "2"].

        Raises:
            NmapNotFoundError: Nmap binary'si sistemde bulunamazsa.
        """
        self.timeout = timeout
        self.extra_flags: list[str] = extra_flags or []
        self.nmap_path: str = self._resolve_nmap_path(nmap_path)
        logger.debug("AsyncScanner başlatıldı. nmap_path=%s", self.nmap_path)

    # ------------------------------------------------------------------
    # Dahili yardımcı metotlar
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_nmap_path(nmap_path: str | None) -> str:
        """Nmap binary'sinin çalıştırılabilir yolunu bulur ve doğrular.

        Args:
            nmap_path: Kullanıcının belirttiği yol; None ise PATH'te arar.

        Returns:
            Nmap binary'sinin doğrulanmış tam yolu.

        Raises:
            NmapNotFoundError: Binary bulunamazsa.
        """
        resolved = nmap_path or shutil.which("nmap")
        if not resolved:
            raise NmapNotFoundError(
                "Nmap binary'si sistemde bulunamadı. "
                "Lütfen Nmap'i yükleyin veya 'nmap_path' parametresiyle "
                "binary'nin tam yolunu belirtin."
            )
        return resolved

    @staticmethod
    def _validate_target(target: str) -> str:
        """Hedef değerinin IP adresi veya geçerli bir hostname olduğunu doğrular.

        IP adresleri için Python'un ipaddress modülü kullanılır.
        Hostname'ler temel karakter geçerliliği açısından kontrol edilir.

        Args:
            target: Doğrulanacak IP adresi veya hostname dizgesi.

        Returns:
            Baştaki/sondaki boşluklardan arındırılmış hedef dizgesi.

        Raises:
            InvalidTargetError: Hedef boş veya geçersiz karakterler içeriyorsa.
        """
        target = target.strip()
        if not target:
            raise InvalidTargetError("Hedef boş olamaz.")

        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            pass

        allowed_chars = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789.-_/"
        )
        if not all(c in allowed_chars for c in target):
            raise InvalidTargetError(
                f"Hedef geçersiz karakterler içeriyor: '{target}'"
            )
        return target

    def _build_command(self, target: str) -> list[str]:
        """Çalıştırılacak Nmap komutunu liste formatında oluşturur.

        Args:
            target: Taranacak IP adresi veya hostname.

        Returns:
            asyncio.create_subprocess_exec'e geçirilecek argüman listesi.
        """
        return [self.nmap_path, *_NMAP_FLAGS, *self.extra_flags, target]

    # ------------------------------------------------------------------
    # XML ayrıştırma
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_xml_output(xml_data: str, target: str) -> ScanResult:
        """Nmap XML çıktısını ayrıştırarak yapılandırılmış bir ScanResult döndürür.

        Args:
            xml_data: Nmap'in stdout'una yazdığı ham XML dizgesi.
            target: Orijinal hedef (XML'de host bulunamazsa kullanılır).

        Returns:
            Hedefin durumunu ve açık portlarını içeren ScanResult nesnesi.

        Raises:
            ET.ParseError: XML geçersiz biçimde ise.
        """
        root = ET.fromstring(xml_data)

        host_element = root.find("host")
        if host_element is None:
            logger.warning("XML çıktısında host elementi bulunamadı: %s", target)
            return ScanResult(target_ip=target, status="down")

        resolved_ip = AsyncScanner._extract_ip(host_element, target)
        status = AsyncScanner._extract_status(host_element)
        open_ports = AsyncScanner._extract_ports(host_element)

        return ScanResult(
            target_ip=resolved_ip,
            status=status,
            open_ports=open_ports,
        )

    @staticmethod
    def _extract_ip(host_element: ET.Element, fallback: str) -> str:
        """Host elementinden IP adresini çıkarır.

        Args:
            host_element: <host> XML elementi.
            fallback: IP bulunamazsa kullanılacak yedek değer.

        Returns:
            Bulunan IP adresi veya fallback değeri.
        """
        address_element = host_element.find("address[@addrtype='ipv4']")
        if address_element is None:
            address_element = host_element.find("address[@addrtype='ipv6']")
        if address_element is not None:
            return address_element.get("addr", fallback)
        return fallback

    @staticmethod
    def _extract_status(host_element: ET.Element) -> str:
        """Host elementinden durum bilgisini çıkarır.

        Args:
            host_element: <host> XML elementi.

        Returns:
            "up" veya "down" dizgesi.
        """
        status_element = host_element.find("status")
        if status_element is not None:
            return status_element.get("state", "down")
        return "down"

    @staticmethod
    def _extract_ports(host_element: ET.Element) -> list[PortInfo]:
        """Host elementinden açık port bilgilerini çıkarır.

        Args:
            host_element: <host> XML elementi.

        Returns:
            Açık portlara ait PortInfo nesnelerinin listesi.
        """
        ports: list[PortInfo] = []
        ports_element = host_element.find("ports")
        if ports_element is None:
            return ports

        for port_element in ports_element.findall("port"):
            state_element = port_element.find("state")
            if state_element is None:
                continue
            if state_element.get("state") != "open":
                continue

            portid_str = port_element.get("portid", "0")
            service_element = port_element.find("service")

            service_name = ""
            product = ""
            version = ""

            if service_element is not None:
                service_name = service_element.get("name", "")
                product = service_element.get("product", "")
                version = service_element.get("version", "")

            try:
                portid = int(portid_str)
            except ValueError:
                logger.warning("Geçersiz port numarası: '%s'", portid_str)
                continue

            ports.append(
                PortInfo(
                    portid=portid,
                    service_name=service_name,
                    product=product,
                    version=version,
                )
            )

        return ports

    # ------------------------------------------------------------------
    # Ana tarama metodu
    # ------------------------------------------------------------------

    async def scan_target(self, target: str) -> dict:
        """Belirtilen hedefi Nmap ile asenkron olarak tarar.

        Nmap'i `-sV --script=banner -oX -` argümanlarıyla doğrudan bir
        alt süreç olarak başlatır. Çıktıyı XML formatında alarak ayrıştırır
        ve yapılandırılmış bir sözlük olarak döndürür.

        Bu metot asyncio.gather veya asyncio.Queue ile eş zamanlı
        kullanım için tamamen güvenlidir.

        Args:
            target: Taranacak hedef; IPv4 adresi, IPv6 adresi, CIDR
                notasyonundaki ağ aralığı (örn. "192.168.1.0/24") veya
                hostname olabilir.

        Returns:
            Aşağıdaki anahtarları içeren sözlük::

                {
                    "target_ip": "192.168.1.1",
                    "status": "up",
                    "open_ports": [
                        {
                            "portid": 80,
                            "service_name": "http",
                            "product": "Apache httpd",
                            "version": "2.4.51"
                        },
                        ...
                    ]
                }

        Raises:
            InvalidTargetError: Hedef IP adresi veya hostname geçersizse.
            NmapNotFoundError: Nmap binary'si çalıştırılamıyorsa.
            ScanTimeoutError: Tarama belirlenen timeout süresini aşarsa.
            RuntimeError: Nmap sıfır dışı çıkış kodu döndürürse.
        """
        validated_target = self._validate_target(target)
        command = self._build_command(validated_target)

        logger.info("Tarama başlatılıyor: %s", validated_target)
        logger.debug("Çalıştırılan komut: %s", " ".join(command))

        process: asyncio.subprocess.Process | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise ScanTimeoutError(
                    f"'{validated_target}' için tarama {self.timeout} saniye "
                    "içinde tamamlanamadı."
                )

            return_code = process.returncode
            if return_code != 0:
                stderr_text = stderr_bytes.decode(errors="replace").strip()
                raise RuntimeError(
                    f"Nmap '{validated_target}' için {return_code} çıkış kodu "
                    f"döndürdü. Stderr: {stderr_text}"
                )

            xml_output = stdout_bytes.decode(errors="replace")
            if not xml_output.strip():
                logger.warning(
                    "'%s' için Nmap çıktısı boş döndü.", validated_target
                )
                return ScanResult(
                    target_ip=validated_target, status="down"
                ).to_dict()

            scan_result = self._parse_xml_output(xml_output, validated_target)
            logger.info(
                "Tarama tamamlandı: %s | Durum: %s | Açık port sayısı: %d",
                validated_target,
                scan_result.status,
                len(scan_result.open_ports),
            )
            return scan_result.to_dict()

        except (InvalidTargetError, ScanTimeoutError, RuntimeError):
            raise
        except FileNotFoundError as exc:
            raise NmapNotFoundError(
                f"Nmap binary'si çalıştırılamadı: '{self.nmap_path}'. "
                "Binary'nin var olduğundan ve çalıştırma iznine sahip "
                "olduğundan emin olun."
            ) from exc
        except ET.ParseError as exc:
            logger.error(
                "'%s' için Nmap XML çıktısı ayrıştırılamadı: %s",
                validated_target,
                exc,
            )
            return ScanResult(
                target_ip=validated_target, status="down"
            ).to_dict()
        except OSError as exc:
            raise RuntimeError(
                f"'{validated_target}' taraması sırasında işletim sistemi "
                f"hatası oluştu: {exc}"
            ) from exc
        finally:
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                    await process.wait()
                    logger.debug(
                        "Nmap süreci temizlendi: %s", validated_target
                    )
                except ProcessLookupError:
                    pass

    async def scan_targets_batch(
        self,
        targets: list[str],
        concurrency: int = 10,
    ) -> list[dict]:
        """Birden fazla hedefi eş zamanlı olarak asyncio.Queue ile tarar.

        asyncio.gather'dan farklı olarak bu metot, eş zamanlı çalışan
        görev sayısını 'concurrency' parametresiyle sınırlar. Büyük
        hedef listeleri için kaynak kullanımını kontrol altında tutar.

        Args:
            targets: Taranacak hedef listesi.
            concurrency: Aynı anda çalışacak maksimum tarama sayısı.
                Varsayılan: 10.

        Returns:
            Her hedefe karşılık gelen tarama sonucu sözlüklerinin listesi.
            Sıra, giriş listesiyle örtüşmeyebilir; başarısız taramalar
            "down" statüsüyle sonuç listesine dahil edilir.
        """
        queue: asyncio.Queue[str] = asyncio.Queue()
        results: list[dict] = []
        lock = asyncio.Lock()

        for t in targets:
            await queue.put(t)

        async def worker() -> None:
            while True:
                try:
                    t = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                try:
                    result = await self.scan_target(t)
                except Exception as exc:
                    logger.error(
                        "'%s' taraması başarısız oldu: %s", t, exc
                    )
                    result = ScanResult(
                        target_ip=t, status="down"
                    ).to_dict()
                finally:
                    async with lock:
                        results.append(result)
                    queue.task_done()

        workers = [
            asyncio.create_task(worker())
            for _ in range(min(concurrency, len(targets)))
        ]
        await asyncio.gather(*workers)
        return results
