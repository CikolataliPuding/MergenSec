"""MergenSec NVD entegrasyon demo scripti.

Senaryo: "Port 80 açık, servis: Apache httpd 2.4.41"
Bu script, Nmap çıktısını simüle ederek NVD'den CVE listesi çeker.

Çalıştırmak için:
    python demo_nvd.py
"""

import asyncio
import logging

from src.cve import NVDClient, CPEBuilder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# Nmap'ten gelen simüle edilmiş port verisi
SIMULATED_NMAP_OUTPUT = {
    "target_ip": "192.168.1.100",
    "status": "up",
    "open_ports": [
        {
            "portid": 80,
            "service_name": "http",
            "product": "Apache httpd",
            "version": "2.4.41",
        }
    ],
}


async def main() -> None:
    print("=" * 60)
    print("MergenSec - NVD CVE Entegrasyon Demo")
    print("=" * 60)

    port_info = SIMULATED_NMAP_OUTPUT["open_ports"][0]
    product = port_info["product"]
    version = port_info["version"]

    # Adım 1: CPE oluştur
    cpe = CPEBuilder.build(product, version)
    print(f"\n[1] Nmap Verisi  : {product} {version}")
    print(f"    CPE 2.3      : {cpe}")

    # Adım 2: NVD'yi sorgula
    print(f"\n[2] NVD sorgulanıyor...")
    async with NVDClient(results_per_page=10) as client:
        result = await client.get_cves_for_service(product, version)

    # Adım 3: Sonuçları göster
    print(f"\n[3] Sonuçlar")
    print(f"    Toplam CVE   : {result.total_results}")
    print(f"    Gösterilen   : {len(result.cves)}")
    print()

    if not result.cves:
        print("    Bu versiyon için CVE bulunamadı.")
        return

    print(f"{'CVE ID':<20} {'CVSS':>6}  {'Önem':<10}  {'Tarih':<12}")
    print("-" * 60)
    for cve in result.cves:
        score_str = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
        severity_str = cve.severity or "N/A"
        date_str = cve.published[:10] if cve.published else "N/A"
        print(f"{cve.cve_id:<20} {score_str:>6}  {severity_str:<10}  {date_str:<12}")

    print()
    # En yüksek skorlu CVE'nin açıklamasını göster
    top_cve = max(
        (c for c in result.cves if c.cvss_score is not None),
        key=lambda c: c.cvss_score,
        default=result.cves[0],
    )
    print(f"En kritik CVE: {top_cve.cve_id} (CVSS: {top_cve.cvss_score})")
    print(f"Açıklama: {top_cve.description[:200]}...")


if __name__ == "__main__":
    asyncio.run(main())
