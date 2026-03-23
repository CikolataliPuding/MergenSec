# MergenSec: High-Precision Autonomous Vulnerability Mapping Framework  
**"Wisdom in Scanning, Precision in Defense."**

MergenSec is a sophisticated security auditing tool inspired by *Mergen*, the deity of wisdom and archery in Turkic mythology. It is engineered to provide high-precision network scanning and autonomous vulnerability identification, bridging the gap between raw network data and actionable security intelligence.

---

## Project Concept

The primary goal of MergenSec is to empower organizations by automating the detection of known vulnerabilities. By leveraging modern Python libraries and asynchronous programming, the framework minimizes manual effort while enabling faster and more reliable security assessments.

---

## Key Features

- **Asynchronous Network Discovery**  
  Utilizes `python-nmap` to perform high-speed, non-blocking scans of active services on target systems.

- **Intelligent CVE Mapping**  
  Integrates with the National Vulnerability Database (NVD) API to match detected service versions with real-world CVEs.

- **Interactive Visualization**  
  A dynamic dashboard powered by `Streamlit` to display:
  - Risk levels (Critical, High, Medium, Low)
  - CVSS scores
  - Detailed vulnerability insights

- **Professional Reporting**  
  Generates structured JSON reports for integration with other security tools and workflows.

---

## System Logic

MergenSec follows a streamlined three-step workflow:

### Input
The user provides:
- A single IP address  
- Or a network range (e.g., `192.168.1.0/24`)

### Process
- Performs asynchronous network scanning  
- Extracts service/banner information  
- Queries CVE databases for known vulnerabilities  

### Output
- Displays results in an interactive dashboard  
- Exports findings as a structured security report  

---

## Technical Stack

The project is built using **Python 3.12+** and follows clean coding standards (PEP 8).

| Component            | Technology            | Purpose                                      |
|---------------------|----------------------|----------------------------------------------|
| Core Language       | Python 3.12+         | Main development language                    |
| Concurrency         | asyncio, aiohttp     | High-speed asynchronous operations           |
| Network Scanning    | python-nmap          | Service and port discovery                   |
| Data Intelligence   | NVD API (CVE/CPE)    | Vulnerability data retrieval                 |
| Data Processing     | Pandas               | Data structuring and analysis                |
| Database            | SQLAlchemy           | Local storage and caching                    |
| User Interface      | Streamlit            | Web-based dashboard                          |
| Testing             | Pytest               | Unit testing and validation                  |

---

## Development Team

- **Egemen Korkmaz** – Lead Developer & Scrum Master  
- **Zid Alkahni** – Backend Developer  
- **Mustafa Bite** – Cybersecurity Developer  
- **Selameddin Tirit** – Integration & Support Developer  
- **Çağrı Doğan** – Integration & Support Developer  

---

## Vision

MergenSec aims to evolve into a fully autonomous security intelligence system that not only detects vulnerabilities but also prioritizes and suggests mitigation strategies.

---