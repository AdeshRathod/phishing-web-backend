# # utils.py
# from urllib.parse import urlparse
# import re
# import socket
# import requests
# from bs4 import BeautifulSoup

# def has_ip_address(url):
#     try:
#         ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
#         return 1 if re.search(ip_pattern, url) else 0
#     except Exception:
#         return 0

# def long_url(url):
#     return 1 if len(url) >= 75 else 0

# def short_url(url):
#     return 1 if len(url) <= 54 else 0

# def has_symbol_at(url):
#     return 1 if "@" in url else 0

# def redirecting_double_slash(url):
#     return 1 if url.count('//') > 1 else 0

# def prefix_suffix(url):
#     domain = urlparse(url).netloc
#     return 1 if '-' in domain else 0

# def sub_domains(url):
#     domain = urlparse(url).netloc
#     return 1 if domain.count('.') > 1 else 0

# def uses_https(url):
#     return 1 if urlparse(url).scheme == 'https' else 0

# def domain_reg_len(url):
#     # Placeholder - need WHOIS info
#     return 0

# def favicon(url):
#     try:
#         response = requests.get(url, timeout=5)
#         soup = BeautifulSoup(response.content, 'html.parser')
#         icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
#         if icon_link:
#             icon_href = icon_link.get('href')
#             if icon_href:
#                 favicon_domain = urlparse(icon_href).netloc
#                 page_domain = urlparse(url).netloc
#                 return 1 if favicon_domain and favicon_domain != page_domain else 0
#         return 0
#     except Exception:
#         return 0

# def non_std_port(url):
#     parsed = urlparse(url)
#     if parsed.port:
#         return 1 if parsed.port not in (80, 443) else 0
#     return 0

# def https_domain_url(url):
#     domain = urlparse(url).netloc
#     return 1 if "https" in domain else 0

# def request_url(url):
#     # Simplified: assume safe
#     return 0

# def anchor_url(url):
#     # Simplified: assume safe
#     return 0

# def links_in_script_tags(url):
#     # Simplified: assume safe
#     return 0

# def server_form_handler(url):
#     # Simplified: assume safe
#     return 0

# def info_email(url):
#     return 1 if "mailto:" in url else 0

# def abnormal_url(url):
#     # Placeholder
#     return 0

# def website_forwarding(url):
#     # Placeholder
#     return 0

# def status_bar_cust(url):
#     # Placeholder
#     return 0

# def disable_right_click(url):
#     # Placeholder
#     return 0

# def popup_window(url):
#     # Placeholder
#     return 0

# def iframe_redirection(url):
#     # Placeholder
#     return 0

# def age_of_domain(url):
#     # Placeholder
#     return 0

# def dns_recording(url):
#     # Placeholder
#     return 0

# def website_traffic(url):
#     # Simplified: Assume site has traffic
#     return 1

# def page_rank(url):
#     # Simplified: Assume good rank
#     return 1

# def google_index(url):
#     return 1

# def links_pointing_to_page(url):
#     return 1

# def stats_report(url):
#     return 0

# def extract_features(url):
#     return [
#         has_ip_address(url),
#         long_url(url),
#         short_url(url),
#         has_symbol_at(url),
#         redirecting_double_slash(url),
#         prefix_suffix(url),
#         sub_domains(url)
#     ]


## multiple data sets
import re
from urllib.parse import urlparse

def has_ip_address(url): return int(bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url)))
def long_url(url): return int(len(url) >= 75)
def short_url(url): return int(len(url) <= 54)
def has_symbol_at(url): return int('@' in url)
def redirecting_double_slash(url): return int(url.count('//') > 1)
def prefix_suffix(url): return int('-' in urlparse(url).netloc)
def sub_domains(url): return int(urlparse(url).netloc.count('.') > 2)
def uses_https(url): return int(urlparse(url).scheme == 'https')
def https_in_domain(url): return int('https' in urlparse(url).netloc)
def domain_length(url): return len(urlparse(url).netloc)
def path_length(url): return len(urlparse(url).path)
def has_suspicious_words(url):
    keywords = ['secure', 'login', 'signin', 'bank', 'update', 'verify', 'account']
    return int(any(word in url.lower() for word in keywords))
def count_special_chars(url): return sum(url.count(c) for c in ['.', '-', '_', '=', '?', '&'])

def extract_features(url):
    return [
        has_ip_address(url),
        long_url(url),
        short_url(url),
        has_symbol_at(url),
        redirecting_double_slash(url),
        prefix_suffix(url),
        sub_domains(url),
        uses_https(url),
        https_in_domain(url),
        domain_length(url),
        path_length(url),
        has_suspicious_words(url),
        count_special_chars(url),
    ]

def extract_features_dict(url):
    return {
        'has_ip': has_ip_address(url),
        'long_url': long_url(url),
        'short_url': short_url(url),
        'has_symbol_at': has_symbol_at(url),
        'redirecting_double_slash': redirecting_double_slash(url),
        'prefix_suffix': prefix_suffix(url),
        'sub_domains': sub_domains(url),
        'uses_https': uses_https(url),
        'https_in_domain': https_in_domain(url),
        'domain_length': domain_length(url),
        'path_length': path_length(url),
        'has_suspicious_words': has_suspicious_words(url),
        'count_special_chars': count_special_chars(url),
    }
