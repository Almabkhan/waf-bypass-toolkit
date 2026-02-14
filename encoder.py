#!/usr/bin/env python3
"""
Payload Encoder - Educational Tool
Encode payloads for WAF bypass
"""

import urllib.parse
import base64
import binascii

class PayloadEncoder:
    def __init__(self):
        self.encodings = {
            'URL': self.url_encode,
            'Double URL': self.double_url_encode,
            'Base64': self.base64_encode,
            'Hex': self.hex_encode,
            'HTML': self.html_encode
        }
    
    def url_encode(self, payload):
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    def double_url_encode(self, payload):
        """Double URL encode payload"""
        once = urllib.parse.quote(payload)
        return urllib.parse.quote(once)
    
    def base64_encode(self, payload):
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    def hex_encode(self, payload):
        """Hex encode payload"""
        return payload.encode().hex()
    
    def html_encode(self, payload):
        """HTML entity encode payload"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def encode_all(self, payload):
        """Encode payload in all formats"""
        results = {}
        for name, encoder in self.encodings.items():
            try:
                results[name] = encoder(payload)
            except:
                results[name] = "Encoding failed"
        return results
    
    def demonstrate(self, payload):
        """Demonstrate all encodings"""
        print("="*70)
        print(f"🔤 Original Payload: {payload}")
        print("="*70)
        
        results = self.encode_all(payload)
        
        for encoding, encoded in results.items():
            print(f"\n📌 {encoding} Encoding:")
            print(f"   {encoded}")
            print(f"   Length: {len(encoded)} chars")

def main():
    encoder = PayloadEncoder()
    
    print("="*70)
    print("🔄 PAYLOAD ENCODER - WAF Bypass Tool")
    print("="*70)
    
    payload = input("\nEnter payload to encode: ").strip()
    
    if payload:
        encoder.demonstrate(payload)
    else:
        # Demo payloads
        test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd"
        ]
        
        print("\n📋 Demo Payloads:")
        for i, payload in enumerate(test_payloads, 1):
            print(f"\n{i}. {payload}")
            results = encoder.encode_all(payload)
            for enc, encoded in list(results.items())[:2]:  # Show first 2
                print(f"   {enc}: {encoded[:50]}...")

if __name__ == "__main__":
    main()