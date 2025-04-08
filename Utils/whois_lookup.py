import whois

def get_whois_details(url):
    try:
        domain_info = whois.whois(url)
        whois_data = {
            "registrar": domain_info.registrar,
            "status": domain_info.status,
            "expiration_date": str(domain_info.expiration_date),
            "updated_date": str(domain_info.updated_date),
            "name_servers": domain_info.name_servers,
            "emails": domain_info.emails,
            "organization": domain_info.org,
            "country": domain_info.country
        }
        return whois_data
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        return None
