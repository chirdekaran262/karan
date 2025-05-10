import re
import pandas as pd
from urllib.parse import urlparse
import whois  # Make sure to install this package: pip install python-whois
import requests

# Define expected features based on your model's training data
expected_features = [
    'index',
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
    # 'Result'
]

def extract_features(url):
    features = {}
    features['index'] = 0  # Placeholder for index, can be set to a unique value if needed
    # URL features
    features['having_IPhaving_IP_Address'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    features['URLURL_Length'] = len(url)
    features['Shortining_Service'] = int(bool(re.search(r'(bit\.ly|tinyurl\.com|is\.gd|t\.co)', url)))
    features['having_At_Symbol'] = int('@' in url)
    features['double_slash_redirecting'] = int(url.count('//') > 2)
    features['Prefix_Suffix'] = int(bool(re.search(r'[-_]+$', url) or re.search(r'^[-_]+', url)))
    features['having_Sub_Domain'] = int(bool(urlparse(url).netloc.count('.') > 1))
    features['SSLfinal_State'] = int(url.startswith('https://'))
    
    # Placeholder for actual domain registration length
    features['Domain_registeration_length'] = -1  
    
    # Check domain registration length using whois
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        features['Domain_registeration_length'] = (pd.Timestamp.now() - pd.Timestamp(domain_info.creation_date)).days if isinstance(domain_info.creation_date, list) else (pd.Timestamp.now() - pd.Timestamp(domain_info.creation_date)).days
    except Exception:
        features['Domain_registeration_length'] = -1  # Error or domain not found

    features['Favicon'] = int(bool(re.search(r'favicon.ico', url)))
    features['port'] = int(urlparse(url).port is not None)
    features['HTTPS_token'] = int('https' in url)

    # URL-based features
    features['Request_URL'] = int(bool(re.search(r'[\w.-]+\.[\w.-]+', url)))
    features['URL_of_Anchor'] = int(bool(re.search(r'<a href=["\']([^"\']+)["\']', url)))
    features['Links_in_tags'] = int(bool(re.search(r'<link', url)))

    # Additional specific features
    features['SFH'] = int(bool(re.search(r'form action=["\']?([^"\'>]+)', url)))
    features['Submitting_to_email'] = int(bool(re.search(r'[\w.-]+@[\w.-]+', url)))
    features['Abnormal_URL'] = int(bool(re.search(r'[^a-zA-Z0-9./-_]', url)))
    features['Redirect'] = int(bool(re.search(r'http[s]?://[^/]+/redirect', url)))
    features['on_mouseover'] = int(bool(re.search(r'onmouseover', url)))
    features['RightClick'] = int(bool(re.search(r'oncontextmenu', url)))
    features['popUpWidnow'] = int(bool(re.search(r'window.open', url)))
    features['Iframe'] = int(bool(re.search(r'<iframe', url)))

    # Age of domain
    try:
        domain_info = whois.whois(urlparse(url).netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['age_of_domain'] = (pd.Timestamp.now() - pd.Timestamp(creation_date)).days
    except Exception:
        features['age_of_domain'] = -1  # Error or domain not found

    # DNS Record (checking if the domain resolves)
    try:
        response = requests.get(url, timeout=5)
        features['DNSRecord'] = int(response.status_code == 200)
    except requests.RequestException:
        features['DNSRecord'] = 0

    # Placeholders for additional data
    features['web_traffic'] = -1  
    features['Page_Rank'] = -1  
    features['Google_Index'] = -1  
    features['Links_pointing_to_page'] = -1  
    features['Statistical_report'] = -1  
    # features['Result'] = -1  # Placeholder, update based on actual classification

    return pd.DataFrame([features], columns=expected_features)

# Testing the function
# test_url = 'http://example.com'  # Replace with an actual URL to test
# features_df = extract_features(test_url)
# print(features_df)
# print(features_df.shape)  # This should print (1, 31)
