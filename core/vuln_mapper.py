# core/vuln_mapper.py

# Basit servis eşleştirme
def get_service(port):
    if port == 80:
        return "http"
    elif port == 22:
        return "ssh"
    elif port == 21:
        return "ftp"
    else:
        return None


# Basit CVE veritabanı
CVE_DB = {
    "http": {
        "cve": "CVE-2021-41773",
        "description": "Apache Path Traversal",
        "cvss": 7.5
    },
    "ssh": {
        "cve": "CVE-2018-15473",
        "description": "OpenSSH User Enumeration",
        "cvss": 5.3
    },
    "ftp": {
        "cve": "CVE-2015-3306",
        "description": "ProFTPd Remote Code Execution",
        "cvss": 9.8
    }
}


def map_vulnerability(port):
    service = get_service(port)

    if service in CVE_DB:
        data = CVE_DB[service]

        return {
            "port": port,
            "service": service,
            "cve": data["cve"],
            "description": data["description"],
            "cvss": data["cvss"]
        }

    return None
if __name__ == "__main__":
    test_ports = [21, 22, 80]

    for port in test_ports:
        result = map_vulnerability(port)
        if result:
            print(result)