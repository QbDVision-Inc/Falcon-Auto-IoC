import requests
import json
import datetime
import csv
import yaml
from tqdm import tqdm
from urllib.parse import urlparse
import ipaddress


def main():
    # Load sources and Falcon API token from YAML file
    with open('sources.yaml', 'r') as yaml_file:
        config = yaml.safe_load(yaml_file)
        source_urls = config.get('sources', [])
        falcon_api_token = config.get('falcon_api_token')

    if not source_urls:
        print("No sources found in sources.yaml")
        return

    if not falcon_api_token:
        print("Falcon API token not found in sources.yaml")
        return

    # Ask the user for the date range
    choice = input("Do you want to download data for the last 15 days? (yes/no): ").strip().lower()
    if choice in ['yes', 'y']:
        # Get date range for last 15 days
        start_date = datetime.date.today() - datetime.timedelta(days=15)
        end_date = datetime.date.today() - datetime.timedelta(days=1)  # Yesterday
        date_list = [start_date + datetime.timedelta(days=x) for x in range((end_date - start_date).days + 1)]
        date_str_list = [date.strftime('%Y-%m-%d') for date in date_list]
    else:
        # Only yesterday
        date_str_list = [(datetime.date.today() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')]

    all_rows = []

    # Loop through each source URL
    for manifest_url in source_urls:
        print(f"Processing source: {manifest_url}")

        # Download manifest JSON
        try:
            response = requests.get(manifest_url)
            response.raise_for_status()
            manifest = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching manifest from {manifest_url}: {e}")
            continue

        # Filter manifest entries by date
        relevant_uuids = [uuid for uuid, event_info in manifest.items() if event_info.get('date') in date_str_list]

        # Determine the base URL for event JSON files
        base_url = manifest_url.rsplit('/', 1)[0]

        # Progress bar for downloading and processing events
        for uuid in tqdm(relevant_uuids, desc="Processing events", unit="event"):
            # Proceed with download and analysis
            json_url = f'{base_url}/{uuid}.json'
            try:
                event_response = requests.get(json_url)
                event_response.raise_for_status()
                event_json = event_response.json()
                process_event(event_json, all_rows)
            except requests.exceptions.RequestException as e:
                print(f"Error fetching event data for {uuid}: {e}")

    # Remove duplicates from all_rows
    unique_rows = []
    seen_keys = set()
    for row in all_rows:
        key = get_row_key(row)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_rows.append(row)

    # Open CSV file for writing
    csv_filename = 'output.csv'
    fieldnames = ['Type', 'value', 'description', 'platforms', 'applied_globally', 'severity', 'action',
                  'metadata.filename']
    with open(csv_filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in unique_rows:
            writer.writerow(row)

    print(f"CSV file '{csv_filename}' has been generated with {len(unique_rows)} records.")

    # Ask the user if they want to send the data to Falcon API
    choice = input("Do you want to send each record via POST request to Falcon API? (yes/no): ").strip().lower()
    if choice in ['yes', 'y']:
        send_data_to_falcon_api(unique_rows, falcon_api_token)
    else:
        print("Data not sent to Falcon API.")


def process_event(event_json, all_rows):
    event = event_json.get('Event', {})

    # Check if 'Object' exists
    if 'Object' in event and event['Object']:
        # Process attributes nested within objects
        objects = event['Object']
        for obj in objects:
            attributes = obj.get('Attribute', [])
            filename = None

            # Try to find filename in the attributes
            for attr in attributes:
                if attr.get('type') == 'filename':
                    filename = attr.get('value')
                    break  # Assuming one filename per object

            if not filename:
                # Try to get filename from object comment
                filename = obj.get('comment', '')

            # Now process other attributes
            process_attributes(attributes, filename, all_rows)
    elif 'Attribute' in event and event['Attribute']:
        # Process attributes directly under the event
        attributes = event['Attribute']
        filename = event.get('info', '')  # Use event info as filename if available
        process_attributes(attributes, filename, all_rows)
    else:
        # No attributes found
        pass


def process_attributes(attributes, filename, all_rows):
    for attr in attributes:
        attr_type = attr.get('type')
        value = attr.get('value')
        description = attr.get('comment', '')

        if attr_type == 'ip-dst|port':
            # Extract IP address and determine if it's IPv4 or IPv6
            ip_value = value.split('|')[0]
            ip_type = determine_ip_type(ip_value)
            if ip_type:
                attr_type_processed = ip_type
                value_processed = ip_value
            else:
                continue  # Skip if IP address is invalid
        elif attr_type == 'url':
            # Extract domain from URL and check if it's an IP address
            parsed_url = urlparse(value)
            domain_or_ip = parsed_url.hostname
            if domain_or_ip:
                ip_type = determine_ip_type(domain_or_ip)
                if ip_type:
                    attr_type_processed = ip_type
                    value_processed = domain_or_ip
                else:
                    attr_type_processed = 'domain'
                    value_processed = domain_or_ip
            else:
                continue  # Skip if domain extraction fails
        elif attr_type in ['sha256', 'md5', 'domain', 'ipv4', 'ipv6']:
            value_processed = value
            if attr_type == 'domain':
                # Check if the domain is actually an IP address
                ip_type = determine_ip_type(value_processed)
                if ip_type:
                    attr_type_processed = ip_type
                else:
                    attr_type_processed = 'domain'
            else:
                attr_type_processed = attr_type
        else:
            continue  # Skip other types

        # If attr_type_processed is sha256 or md5, check that the value is valid
        if attr_type_processed in ['sha256', 'md5']:
            if not is_valid_hash(value_processed, attr_type_processed):
                continue  # Skip invalid hashes

        # Build row
        row = {
            'Type': attr_type_processed,
            'value': value_processed,
            'description': description,
            'platforms': 'windows,mac,linux',
            'applied_globally': 'true',
            'severity': 'high',
            'action': 'prevent',
            'metadata.filename': filename or ''
        }
        all_rows.append(row)


def determine_ip_type(value):
    try:
        ip_obj = ipaddress.ip_address(value)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return 'ipv4'
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return 'ipv6'
    except ValueError:
        return None  # Not an IP address


def is_valid_hash(hash_value, hash_type):
    if hash_type == 'md5':
        # MD5 hashes are 32 hexadecimal characters
        return len(hash_value) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_value)
    elif hash_type == 'sha256':
        # SHA256 hashes are 64 hexadecimal characters
        return len(hash_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_value)
    else:
        return False


def get_row_key(row):
    # Create a key based on significant fields to identify duplicates
    return (row['Type'], row['value'], row['description'], row['metadata.filename'])


def send_data_to_falcon_api(records, api_token):
    url = 'https://api.crowdstrike.com/iocs/entities/indicators/v1'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_token}'
    }

    # Prepare the data to be sent
    for record in tqdm(records, desc="Sending data to Falcon API", unit="record"):
        indicator = {
            'type': record['Type'],
            'value': record['value'],
            'action': record['action'],
            'severity': record['severity'],
            'description': record['description'],
            'platforms': record['platforms'].split(','),
            'applied_globally': record['applied_globally'].lower() == 'true'
        }

        data = {
            'comment': 'Using abuse.ch',
            'indicators': [indicator]
        }

        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 201 or response.status_code == 200:
                pass  # Successfully created
            else:
                print(f"Failed to send indicator {record['value']}: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Error sending indicator {record['value']}: {e}")


if __name__ == '__main__':
    main()
