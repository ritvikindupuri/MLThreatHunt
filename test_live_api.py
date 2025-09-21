"""
Test the live API to populate CloudWatch dashboard with real metrics
"""

import requests
import json
import time
from datetime import datetime

# Your actual API endpoint
API_ENDPOINT = "https://tmow0ssfke.execute-api.us-east-1.amazonaws.com/prod/analyze"

def test_live_api():
    """
    Test the live API to generate CloudWatch metrics
    """
    print("🚀 TESTING LIVE API TO POPULATE CLOUDWATCH DASHBOARD")
    print("=" * 60)
    print(f"🕐 Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🔗 API Endpoint: {API_ENDPOINT}")
    print("=" * 60)
    
    # Test scenarios
    test_cases = [
        {
            "name": "High-Risk Threat Test",
            "ips": ["185.220.101.1", "192.42.116.16"]
        },
        {
            "name": "Legitimate Infrastructure Test", 
            "ips": ["8.8.8.8", "1.1.1.1"]
        },
        {
            "name": "Mixed Risk Analysis",
            "ips": ["8.8.8.8", "185.220.101.1", "208.67.222.222"]
        }
    ]
    
    successful_calls = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🔍 TEST {i}/3: {test_case['name']}")
        print(f"   IPs: {', '.join(test_case['ips'])}")
        
        # Make API call
        success = make_api_call(test_case['ips'])
        
        if success:
            successful_calls += 1
            print(f"   ✅ API call successful - CloudWatch metrics updated!")
        else:
            print(f"   ❌ API call failed")
        
        # Wait between calls
        if i < len(test_cases):
            print(f"   ⏱️  Waiting 5 seconds...")
            time.sleep(5)
    
    print(f"\n{'='*60}")
    print(f"📊 TEST SUMMARY:")
    print(f"   Successful API Calls: {successful_calls}/{len(test_cases)}")
    print(f"   CloudWatch Dashboard: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=AdvancedThreatHunting")
    print(f"   Lambda Logs: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logsV2:log-groups/log-group/$252Faws$252Flambda$252Fautonomous-ai-threat-hunter")
    
    if successful_calls > 0:
        print(f"\n🎯 SUCCESS! Your CloudWatch dashboard should now show:")
        print(f"   📈 Lambda Invocations: {successful_calls}")
        print(f"   ⚡ Processing Duration metrics")
        print(f"   🚨 Error rates (if any)")
        print(f"   📊 Custom AI metrics")
    else:
        print(f"\n⚠️  No successful calls - let's debug the API")

def make_api_call(ip_addresses):
    """
    Make a real API call to test the system
    """
    payload = {
        "ip_addresses": ip_addresses,
        "analysis_type": "comprehensive"
    }
    
    try:
        print(f"      🚀 Calling API...")
        
        response = requests.post(
            API_ENDPOINT,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        print(f"      📡 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            
            # Show key results
            if result.get('success'):
                processing_time = result.get('processing_time_ms', 0)
                platform_version = result.get('platform_version', 'unknown')
                
                print(f"      ✅ Analysis successful!")
                print(f"      ⚡ Processing Time: {processing_time:.1f}ms")
                print(f"      🤖 Platform: {platform_version}")
                
                # Show threat report summary
                threat_report = result.get('threat_report', {})
                if threat_report:
                    print(f"      🎯 Threat Detection: {threat_report.get('ai_advantages', {}).get('predictive_capability', 'Active')}")
                
                return True
            else:
                print(f"      ❌ Analysis failed: {result.get('error', 'Unknown error')}")
                return False
        else:
            print(f"      ❌ HTTP Error: {response.status_code}")
            print(f"      📄 Response: {response.text[:200]}...")
            return False
            
    except requests.exceptions.Timeout:
        print(f"      ⏰ Request timeout (30s)")
        return False
    except requests.exceptions.ConnectionError:
        print(f"      🌐 Connection error")
        return False
    except Exception as e:
        print(f"      ❌ Error: {str(e)}")
        return False

if __name__ == "__main__":
    test_live_api()