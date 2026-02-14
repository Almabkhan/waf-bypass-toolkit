#!/usr/bin/env python3
"""
WAF Detector - Educational Tool
Detects Web Application Firewalls
"""

import requests # type: ignore
import json

class WAFDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.waf_signatures = {
            'Cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'AWS WAF': ['awselb', 'x-amz-cf-id', 'x-amzn-RequestId'],
            'Sucuri': ['sucuri', 'cloudproxy'],
            'Akamai': ['akamai', 'akamaighost'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Barracuda': ['barracuda'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Wordfence': ['wordfence'],
            'Imperva': ['imperva', 'incapsula'],
            'CloudFront': ['cloudfront', 'x-amz-cf-pop']
        }
        
    def check_headers(self):
        """Check response headers for WAF signatures"""
        try:
            response = self.session.get(self.target_url, timeout=5)
            headers = response.headers
            detected_wafs = []
            
            print("\n[*] Checking Headers...")
            for header, value in headers.items():
                for waf, signatures in self.waf_signatures.items():
                    for sig in signatures:
                        if sig.lower() in header.lower() or sig.lower() in str(value).lower():
                            detected_wafs.append((waf, f"{header}: {value}"))
                            print(f"  [!] Possible {waf} detected: {header}")
            
            return detected_wafs
        except Exception as e:
            print(f"[!] Error: {e}")
            return []
    
    def test_payloads(self, payloads):
        """Test payloads to detect WAF behavior"""
        results = []
        
        print("\n[*] Testing WAF Behavior...")
        for payload in payloads[:5]:  # Test first 5 payloads
            try:
                test_url = f"{self.target_url}?id={payload}"
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 403:
                    results.append({
                        'payload': payload,
                        'status': 403,
                        'result': 'Blocked - WAF detected'
                    })
                    print(f"  [!] Blocked payload: {payload[:30]}...")
                elif response.status_code == 200:
                    results.append({
                        'payload': payload,
                        'status': 200,
                        'result': 'Allowed - Possible bypass'
                    })
            except:
                pass
        
        return results
    
    def generate_report(self):
        """Generate WAF detection report"""
        print("\n" + "="*60)
        print("WAF DETECTION REPORT")
        print("="*60)
        
        headers = self.check_headers()
        
        if headers:
            print(f"\n[+] Detected {len(headers)} WAF signatures:")
            for waf, detail in headers:
                print(f"  • {waf}: {detail}")
        else:
            print("\n[-] No WAF detected in headers")
        
        # Test payloads
        test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "1 UNION SELECT 1,2,3--",
            "'; DROP TABLE users--"
        ]
        
        results = self.test_payloads(test_payloads)
        
        print(f"\n📊 Summary:")
        print(f"  • Total WAF signatures: {len(headers)}")
        print(f"  • Blocked payloads: {sum(1 for r in results if r['status']==403)}")
        print(f"  • Allowed payloads: {sum(1 for r in results if r['status']==200)}")

def main():
    print("="*60)
    print("🛡️ WAF DETECTOR - Educational Tool")
    print("="*60)
    
    target = input("\nEnter target URL (e.g., http://example.com): ").strip()
    
    if not target.startswith("http"):
        target = "http://" + target
    
    detector = WAFDetector(target)
    detector.generate_report()

if __name__ == "__main__":
    main()