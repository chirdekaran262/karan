import re
import pandas as pd
from urllib.parse import urlparse
import whois  # Make sure to install this package: pip install python-whois
import requests
from bs4 import BeautifulSoup  # Make sure to install this package: pip install beautifulsoup4

# Define the features that were selected by the model
# These are the most important features according to your model training
SELECTED_FEATURES = [
    'index',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'URL_of_Anchor',
    'Links_in_tags',
    'web_traffic'
]

# Define all features for compatibility with the model
ALL_FEATURES = [
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
]

def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    Optimized to focus on the selected features from model training
    while maintaining compatibility with the original feature set.
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        pd.DataFrame: A dataframe containing all features for the URL
    """
    features = {}
    
    # Initialize all features with default values
    for feature in ALL_FEATURES:
        features[feature] = 0
    
    # Initialize specific features based on the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Feature: index (placeholder)
    features['index'] = 0
    
    # Feature: having_IPhaving_IP_Address
    features['having_IPhaving_IP_Address'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    
    # Feature: URLURL_Length
    features['URLURL_Length'] = len(url)
    
    # Feature: Shortining_Service
    features['Shortining_Service'] = int(bool(re.search(r'(bit\.ly|tinyurl\.com|is\.gd|t\.co)', url)))
    
    # Feature: having_At_Symbol
    features['having_At_Symbol'] = int('@' in url)
    
    # Feature: double_slash_redirecting
    features['double_slash_redirecting'] = int(url.count('//') > 1)
    
    # Feature: Prefix_Suffix (SELECTED)
    features['Prefix_Suffix'] = int(bool(re.search(r'[-_]+$', url) or re.search(r'^[-_]+', url)))
    
    # Feature: having_Sub_Domain (SELECTED)
    features['having_Sub_Domain'] = int(domain.count('.') > 1)
    
    # Feature: SSLfinal_State (SELECTED)
    features['SSLfinal_State'] = int(url.startswith('https://'))
    
    # Feature: Domain_registeration_length
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            features['Domain_registeration_length'] = (pd.Timestamp.now() - pd.Timestamp(creation_date)).days
        else:
            features['Domain_registeration_length'] = -1
    except Exception:
        features['Domain_registeration_length'] = -1
    
    # Feature: Favicon
    features['Favicon'] = int(bool(re.search(r'favicon\.ico', url)))
    
    # Feature: port
    features['port'] = int(parsed_url.port is not None)
    
    # Feature: HTTPS_token
    features['HTTPS_token'] = int('https' in url.lower())
    
    # Feature: Request_URL
    features['Request_URL'] = int(bool(re.search(r'[\w.-]+\.[\w.-]+', url)))
    
    # Features that require accessing the webpage content
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Feature: URL_of_Anchor (SELECTED)
            anchors = soup.find_all('a', href=True)
            if anchors:
                external_urls = sum(1 for a in anchors if a['href'].startswith(('http', 'https')) 
                                   and domain not in a['href'])
                features['URL_of_Anchor'] = int((external_urls / len(anchors)) > 0.5)
            else:
                features['URL_of_Anchor'] = 0
                
            # Feature: Links_in_tags (SELECTED)
            link_tags = soup.find_all(['link', 'script', 'img'], src=True) + soup.find_all('link', href=True)
            if link_tags:
                external_links = sum(1 for tag in link_tags if 
                                    ('src' in tag.attrs and tag['src'].startswith(('http', 'https')) and domain not in tag['src']) or
                                    ('href' in tag.attrs and tag['href'].startswith(('http', 'https')) and domain not in tag['href']))
                features['Links_in_tags'] = int((external_links / len(link_tags)) > 0.5)
            else:
                features['Links_in_tags'] = 0
                
            # Feature: SFH
            form_tags = soup.find_all('form', action=True)
            features['SFH'] = int(any(form['action'] == "" or form['action'] == "#" or "mailto:" in form['action'] 
                                    for form in form_tags) if form_tags else 0)
            
            # Feature: Submitting_to_email
            features['Submitting_to_email'] = int(any("mailto:" in form.get('action', '') for form in form_tags) if form_tags else 0)
            
            # Feature: Abnormal_URL
            features['Abnormal_URL'] = int(domain not in url)
            
            # Feature: Redirect
            features['Redirect'] = int(response.history != [])
            
            # Feature: on_mouseover
            features['on_mouseover'] = int('onmouseover=' in html_content.lower())
            
            # Feature: RightClick
            features['RightClick'] = int('oncontextmenu=' in html_content.lower() or 'preventdefault' in html_content.lower())
            
            # Feature: popUpWidnow
            features['popUpWidnow'] = int('window.open' in html_content.lower())
            
            # Feature: Iframe
            features['Iframe'] = int(bool(soup.find_all('iframe')))
            
            # Feature: DNSRecord
            features['DNSRecord'] = 1  # We got a response, so DNS exists
            
            # Feature: web_traffic (SELECTED)
            # Since we can't easily get web traffic in real-time without external APIs,
            # we'll use a simplified approach based on domain age
            features['web_traffic'] = int(features['Domain_registeration_length'] > 365)
            
        else:
            # If we can't access the page, mark certain features as suspicious
            features['URL_of_Anchor'] = 1
            features['Links_in_tags'] = 1
            features['DNSRecord'] = 0
            features['web_traffic'] = 0
    
    except Exception:
        # Default values for features that require webpage access
        features['URL_of_Anchor'] = 1
        features['Links_in_tags'] = 1
        features['SFH'] = 1
        features['Submitting_to_email'] = 0
        features['Abnormal_URL'] = 1
        features['Redirect'] = 0
        features['on_mouseover'] = 0
        features['RightClick'] = 0
        features['popUpWidnow'] = 0
        features['Iframe'] = 0
        features['DNSRecord'] = 0
        features['web_traffic'] = 0
    
    # Features that we'll set to default values
    features['age_of_domain'] = int(features['Domain_registeration_length'] > 180) if features['Domain_registeration_length'] > 0 else 0
    features['Page_Rank'] = 0  # Would require external API
    features['Google_Index'] = 0  # Would require external API
    features['Links_pointing_to_page'] = 0  # Would require external API
    features['Statistical_report'] = 0  # Would require external API
    
    # Return as DataFrame
    return pd.DataFrame([features], columns=ALL_FEATURES)

def predict_url(url, model):
    """
    Predict if a URL is phishing or legitimate using the provided model.
    
    Args:
        url (str): The URL to classify
        model: The trained machine learning model
        
    Returns:
        int: 1 for legitimate, -1 for phishing/malicious
    """
    try:
        features_df = extract_features(url)
        prediction = model.predict(features_df)
        return prediction[0]
    except Exception as e:
        print(f"Error predicting URL: {e}")
        return None