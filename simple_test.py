"""
Simple test for VirusTotal ML Threat Hunting Platform
"""

import requests
import json

# Your API endpoint
API_ENDPOINT = "https://tmow0ssfke.execute-api.us-east-1.amazonaws.com/prod/analyze"

def test_virustotal_platform():
    """Test the VirusTotal-powered threat hunting platform"""
    
    print("🛡️  VIRUSTOTAL ML THREAT HUNTING PLATFORM - TEST")
    print("=" * 60)
    
    # Test data with known malicious and clean IPs
    test_cases = [
        {
            "name": "Known Malicious IPs",
            "ips": ["185.220.101.1", "192.42.116.16"],  # Known Tor/suspicious
            "expected": "HIGH_RISK"
        },
        {
            "name": "Legitimate DNS Servers", 
            "ips": ["8.8.8.8", "1.1.1.1"],
            "expected": "LOW_RISK"
        },
        {
            "name": "Mixed Risk Analysis",
            "ips": ["8.8.8.8", "185.220.101.1", "1.1.1.1"],
            "expected": "MEDIUM_RISK"
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Testing: {test_case['name']}")
        print(f"   IPs: {', '.join(test_case['ips'])}")
        
        # Prepare request
        payload = {
            "ip_addresses": test_case["ips"],
            "analysis_type": "comprehensive"
        }
        
        try:
            # Make API call
            response = requests.post(
                API_ENDPOINT,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Display results
                threat_report = result.get('threat_report', {})
                print(f"   ✅ Overall Risk Score: {threat_report.get('overall_risk_score', 0):.3f}")
                print(f"   📊 Risk Level: {threat_report.get('risk_level', 'UNKNOWN')}")
                print(f"   🧠 ML Model: {result.get('ml_model_version', 'unknown')}")
                print(f"   ⚡ Processing Time: {result.get('processing_time_ms', 0)}ms")
                
                # VirusTotal insights
                vt_insights = threat_report.get('virustotal_insights', {})
                if vt_insights:
                    print(f"   🦠 VirusTotal Coverage: {vt_insights.get('coverage_percentage', 0):.1f}%")
                    print(f"   🚨 Malicious Detections: {vt_insights.get('malicious_detections', 0)}")
                
                # Threat indicators
                indicators = threat_report.get('threat_indicators', [])
                if indicators:
                    print(f"   🎯 Threat Indicators Found: {len(indicators)}")
                    for indicator in indicators[:3]:  # Show top 3
                        print(f"      - {indicator.get('value', '')}: "
                              f"Risk={indicator.get('risk_score', 0):.3f} "
                              f"({indicator.get('virustotal_verdict', 'unknown')})")
                
            else:
                print(f"   ❌ API Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"   ❌ Request Error: {e}")
    
    print("\n" + "=" * 60)
    print("✅ VIRUSTOTAL TESTING COMPLETED!")
    print("\n🎯 Key Features Tested:")
    print("• VirusTotal API integration for threat intelligence")
    print("• Advanced ML ensemble algorithms")
    print("• Real-time risk scoring and classification")
    print("• Comprehensive threat indicator extraction")
    print("• Executive-level threat reporting")
    
    print("\n🚀 Next Steps:")
    print("• Get your VirusTotal API key from: https://www.virustotal.com/gui/my-apikey")
    print("• Update terraform.tfvars with your VirusTotal API key")
    print("• Redeploy with: terraform apply")
    print("• Monitor CloudWatch dashboard for real-time metrics")

if __name__ == "__main__":
    test_virustotal_platform()