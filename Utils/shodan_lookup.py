import requests

SHODAN_API_KEY = "YYS9Fd8XftXfieQ3BwnsUieGjKvwqggf"

def search_shodan(ip_address):
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Shodan error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Shodan lookup failed: {e}")
        return None
