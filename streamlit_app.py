import hashlib
import hmac
import requests
import streamlit as st
from datetime import datetime, timezone
import urllib.parse
import pandas as pd

# Helper functions
def canonical_url_encode(url):
    """
    Encodes the URI, encoding '/' as '%2F'.
    """
    encoded = urllib.parse.quote(url, safe='')
    return encoded

def double_encode(s):
    """
    Double-encodes a string to match Postman's encoding.
    Example: '+' -> '%252B'
    """
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')

def generate_signature(access_key, secret_key, method, uri, query_params):
    """
    Generates the HMAC-SHA1 signature required for authentication.
    """
    # Step 1: Create timestamp in ISO 8601 format with milliseconds
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    # Step 2: Use the original order of query parameters (endTime first, then startTime)
    # Encode each key once and each value twice using urllib.parse.quote
    encoded_params = '&'.join(
        f"{urllib.parse.quote(k, safe='')}={double_encode(v)}"
        for k, v in query_params
    )

    # Step 3: Canonicalize the URI
    canonical_uri = canonical_url_encode(uri)

    # Step 4: Construct the canonical request
    request_body = ''  # Empty for GET requests
    hashed_body = hashlib.sha256(request_body.encode()).hexdigest()
    canonical_request = f"{method}&{canonical_uri}&{encoded_params}&{hashed_body}"

    # Step 5: Hash the canonical request using SHA-256
    hashed_canonical_request = hashlib.sha256(canonical_request.encode()).hexdigest()

    # Step 6: Create string to sign
    string_to_sign = f"HMAC-SHA1&{timestamp}&{access_key}&{hashed_canonical_request}"

    # Step 7: Generate HMAC-SHA1 signature
    signature = hmac.new(
        secret_key.encode(),
        string_to_sign.encode(),
        hashlib.sha1
    ).hexdigest()

    return timestamp, signature

# Streamlit app
st.title("API Signature and Request Generator")

# Input fields
access_key = st.text_input("Access Key", value="306EA04B93D5CB4E419B1870966083F2")
secret_key = st.text_input("Secret Key", value="99A1F04D6225BDEF23AA77010A1B0D80ACC5219105D74580F24A561054AE277E", type="password")
site_uid = st.text_input("Site UID", value="b35a79ae-772e-44da-8fd2-d57d456d5442")
base_url = st.text_input("Base URL", value="https://api.dinetime.com")
endpoint = f"/Site/{site_uid}/Metrics/SpeedOfService"
method = 'GET'

# Date selection
start_date = st.date_input("Start Date", value=datetime.now().date())
end_date = st.date_input("End Date", value=datetime.now().date())

# Convert selected dates to ISO format
start_time = f"{start_date}T00:00:00+00:00"
end_time = f"{end_date}T23:59:59+00:00"

params = [
    ('endTime', end_time),
    ('startTime', start_time)
]

# Initialize session state to store the data
if 'page_data' not in st.session_state:
    st.session_state['page_data'] = None

# Generate signature and make API request
if st.button("Generate Signature and Send Request"):
    timestamp, signature = generate_signature(access_key, secret_key, method, endpoint, params)

    # Headers
    headers = {
        'Authorization': f'dinetime-sv2-hmac-sha1 Algorithm=SHA256&Credentials={access_key}&Signature={signature}',
        'x-dinetime-timestamp': timestamp,
        'x-dinetime-signature-version': 'dinetime-sv2-hmac-sha1',
        'Accept': '*/*',
        'User-Agent': 'PythonApp'
    }

    # Make the API request
    try:
        response = requests.get(f"{base_url}{endpoint}", headers=headers, params=params)

        # Display the results
        st.write("Final URL:", response.url)
        st.write("Response Status Code:", response.status_code)

        # Display the response as a table if it's in JSON format
        try:
            data = response.json()

            # Check if 'PageData' exists and contains data
            if 'PageData' in data and isinstance(data['PageData'], list):
                st.session_state['page_data'] = pd.json_normalize(data['PageData'])
            else:
                st.write("No 'PageData' found in the response.")
                st.session_state['page_data'] = None
        except ValueError:
            st.write("Response Text:", response.text)
            st.session_state['page_data'] = None

    except requests.exceptions.RequestException as e:
        st.write(f"An error occurred: {e}")
        st.session_state['page_data'] = None

# If data is available, display the column selector and the table
if st.session_state['page_data'] is not None:
    df = st.session_state['page_data']

    # Let the user select which columns to display
    all_columns = df.columns.tolist()
    selected_columns = st.multiselect(
        "Select columns to display", options=all_columns, default=all_columns
    )

    # Display the DataFrame with the selected columns
    if selected_columns:
        st.table(df[selected_columns])
    else:
        st.write("No columns selected to display.")
