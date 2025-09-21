"""
Test the REAL API and show proof the ML model is working
"""

import requests
import json
import time

# Your actual API endpoint
API_ENDPOINT = "https://tmow0ssfke.execute-api.us-east-1.amazonaws.com/prod/analyze"

def test_real_api():
    """Test the actual API and show it's working"""
    print("🧪 TESTING REAL ML MODEL API")
    print("=" * 50)
    
    # Test payload
    payload = {
        "ip_addresses": ["185.220.101.1", "8.8.8.8", "192.42.116.16"]
    }
    
    print(f"📡 Making API call to: {API_ENDPOINT}")
    print(f"📊 Payload: {json.dumps(payload, indent=2)}")
    
    try:
        # Make the actual API call
        response = requests.post(
            API_ENDPOINT,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        print(f"\n📈 Response Status: {response.status_code}")
        print(f"📄 Response Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"\n✅ SUCCESS! ML Model is working!")
            print(f"📊 Response: {json.dumps(result, indent=2)}")
        else:
            print(f"\n❌ Error: {response.status_code}")
            print(f"📄 Response: {response.text}")
            
    except Exception as e:
        print(f"\n❌ Request failed: {str(e)}")

if __name__ == "__main__":
    test_real_api()