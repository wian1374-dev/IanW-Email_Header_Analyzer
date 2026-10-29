import email
import ipaddress
import re
from requests import get
import argparse
import os
from dotenv import load_dotenv
import json
from datetime import datetime
from typing import Any
import vt
import base64

load_dotenv()

##create arguments and initialize script terminal usage.
#users must provide an ipinfo api token and an eml file
parser = argparse.ArgumentParser(description='Email Header Analysis')
parser.add_argument('-f', '--file', required=True, help='Path to the .eml file')
parser.add_argument('-a', '--api', required=False, help='ipinfo API key')
parser.add_argument('-vt', '--virustotal', required=False, help='VirusTotal API key')
args = parser.parse_args()

ipinfo_token = args.api or os.getenv('IPINFO_TOKEN')
vt_token = args.virustotal or os.getenv('VT_TOKEN')

if not ipinfo_token:
    print('Error: No ipinfo.io API key provided. Use --api or set the IPINFO_TOKEN in a .env file.')
    exit(1)
if not vt_token:
    print('No VirusTotal API key provided. For in-depth URL analysis, use --virustotal.')
with open(args.file, 'rb') as file:
    parsed_email = email.message_from_binary_file(file)
    ##print(parsed_email.keys())

##seperate headers, if the 'Received' list ends up being None, the 'or []'
# evaluates received_header_list to an empty list so that 'for header in received_header_list:' does not throw an error
sender_email = parsed_email['From']
reply_to_email = parsed_email['Reply-To']
if reply_to_email is None:
    reply_to_email = 'No Reply-To e-mail found.'
received_header_list = parsed_email.get_all('Received') or []

##examines the authentication header for a list failed security checks, alerts if any are found
auth_header = parsed_email.get('Authentication-Results', '').lower()
red_flags = ['dkim=none', 'dkim=fail', 'dmarc=fail', 'spf=fail', 'spf=softfail', 'spf=none']
detected_flags = [flag for flag in red_flags if flag in auth_header]
if detected_flags:
    print(f'ALERT: Failed authentication checks detected: {detected_flags}')
else:
    print('Authentication checks passed or none found.')

##compile IPs into a list. uses regex patterns to find standard ipv4 notation within each header and puts them all into a list
ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
extracted_ips = []
for header in received_header_list:
    found_ips = re.findall(ip_pattern, header)
    extracted_ips.extend(found_ips)

header_report: dict[str, Any] = {
    "Sender": sender_email,
    "Reply-To": reply_to_email,
    "Authentication": detected_flags,
    "IP Address": [],
    "Extracted_URLs": []
}

##Finds URLs in the body of the email message and appends them to the report
url_pattern = re.compile(r'https?://[^\s<>"\']+')
for part in parsed_email.walk():
    if part.get_content_type() in ["text/plain", "text/html"]:
        body_bytes = part.get_payload(decode=True)
        if body_bytes:
            body_text = body_bytes.decode(errors='ignore')
            found_urls = re.findall(url_pattern, body_text)

            for url in found_urls:
                #Base64 Encode the URL for the VirusTotal API
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

                #Defang the URL so it is safe to print and store
                defanged_url = url.replace('http', 'hxxp').replace('.', '[.]')

                #Prevent duplicate checks if the URL is in both plain text and HTML layer
                if not any(item.get("URL") == defanged_url for item in header_report["Extracted_URLs"]):

                    #Query VirusTotal using vt-py
                    if vt_token:
                        try:
                            with vt.Client(vt_token) as client:
                                url_obj = client.get_object(f"/urls/{url_id}")
                                stats = url_obj.last_analysis_stats
                                malicious_count = stats.get('malicious', 0)
                                suspicious_count = stats.get('suspicious', 0)
                        except vt.APIError as e:
                            if e.code == "NotFoundError":
                                malicious_count = "Unscanned"
                                suspicious_count = "Unscanned"
                            else:
                                malicious_count = f"Error: {e.code}"
                                suspicious_count = f"Error: {e.code}"
                    else:
                        malicious_count = "No API Key"
                        suspicious_count = "No API Key"

                    #Save the data to the master dictionary
                    url_report_data = {
                        "URL": defanged_url,
                        "Malicious_Detections": malicious_count,
                        "Suspicious_Detections": suspicious_count
                    }
                    header_report["Extracted_URLs"].append(url_report_data)

                    #Print the findings to the terminal on separate lines
                    print(f"\nPayload URL: {defanged_url}")
                    print(f"VT Score: {malicious_count} Malicious, {suspicious_count} Suspicious\n")

##Uses ipinfo API to gather osint about IP addresses
# uses the ipaddress module to only analyze public addresses
for ip in extracted_ips:
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        continue
    if not ip.is_private:
        api_url = f'https://ipinfo.io/{ip}/json'
        headers = {'Authorization': f'Bearer {ipinfo_token}'}
        api_response = get(api_url, headers=headers)
        ip_info = api_response.json()

##establish a failover for each variable in case of one being not found
        ip = str(ip_info.get('ip', 'Unknown IP Address')).replace('.', '[.]')
        hostname = ip_info.get('hostname', 'Unknown Hostname')
        city = ip_info.get('city', 'Unknown City')
        region = ip_info.get('region', 'Unknown Region')
        country = ip_info.get('country', 'Unknown Country')
        loc = ip_info.get('loc', 'Unknown Location')
        org = ip_info.get('org', 'Unknown Organization')
        postal = ip_info.get('postal', 'Unknown Postal Code')
        timezone = ip_info.get('timezone', 'Unknown Timezone')

        ip_report_data = {
            "IP": ip,
            "Hostname": hostname,
            "City": city,
            "Region": region,
            "Country": country,
            "Location": loc,
            "Organization": org,
            "Postal": postal,
            "Timezone": timezone,
        }
        header_report['IP Address'].append(ip_report_data)

        print(f'Sender Information: {sender_email}\nSender IP Address: {ip}\nSender Hostname: {hostname}')
        print(f"Sender Location: {city}, {region}, {country}, {loc}, {org}, {postal}, {timezone}")
        print(f'Found URLs: {header_report["Extracted_URLs"]}')

timecode = datetime.now().strftime('%Y%m%d_%H%M%S')
filename = f'email_forensic_report_{timecode}.json'
save_report_choice = input('\nWould you like to save these findings in a JSON report? (y/n): ').strip().lower()
if save_report_choice in ['y', 'yes']:
    with open(filename, 'w') as json_file:
        json.dump(header_report, json_file, indent=4)
    print(f'Report saved to {filename}')