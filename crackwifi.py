import os
import sys
import hashlib
import hmac
from binascii import a2b_hex, b2a_hex
from scapy.all import rdpcap
from hashlib import pbkdf2_hmac

def check_handshake(packets, bssid):
    """CAP fayldan handshake paketlarini tekshiradi"""
    for pkt in packets:
        if pkt.haslayer('EAPOL'):
            if pkt.addr2.lower() == bssid.lower() or pkt.addr3.lower() == bssid.lower():
                return True
    return False

def crack_wifi(cap_file, wordlist):
    """Asosiy parol sinash funksiyasi"""
    try:
        print(f"WiFi parol sinash boshlandi...")
        print(f"CAP fayl: {cap_file}")
        print(f"Parol fayli: {wordlist}")
        
        # CAP faylni o'qish
        packets = rdpcap(cap_file)
        
        # BSSID ni aniqlash
        bssid = None
        for pkt in packets:
            if pkt.haslayer('Dot11Beacon'):
                bssid = pkt.addr2.lower()
                break
        
        if not bssid:
            print("BSSID topilmadi!")
            return False
        
        print(f"BSSID topildi: {bssid}")
        
        if not check_handshake(packets, bssid):
            print("Handshake topilmadi!")
            return False
        
        print("Handshake paketlari topildi, parol sinash boshlandi...")
        
        # Parol faylini o'qish
        with open(wordlist, 'r', encoding='latin-1', errors='ignore') as f:
            total = sum(1 for _ in f)
            f.seek(0)
            
            for i, password in enumerate(f, 1):
                password = password.strip()
                if not password:
                    continue
                
                # Progress ko'rsatish
                if i % 100 == 0:
                    print(f"Progress: {i}/{total} ({i/total*100:.1f}%) - Sinab ko'rilmoqda: {password[:20]}...")
                
                # PMK ni hisoblash (WPA/WPA2 uchun)
                try:
                    pmk = pbkdf2_hmac(
                        'sha1',
                        password.encode('utf-8', 'ignore'),
                        bssid.encode('utf-8'),
                        4096,
                        32
                    )
                    # Haqiqiy loyihada bu yerda MIC tekshirish bo'lishi kerak
                    # Demo uchun faqat parollarni chiqaramiz
                
                except Exception as e:
                    print(f"Xato: {password} - {str(e)}")
                    continue
        
        print("Parol topilmadi!")
        return False
    
    except Exception as e:
        print(f"Xato yuz berdi: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crackwifi.py <cap_file> <wordlist>")
        sys.exit(1)
    
    cap_file = sys.argv[1]
    wordlist = sys.argv[2]
    
    if not os.path.isfile(cap_file):
        print(f"CAP fayl topilmadi: {cap_file}")
        sys.exit(1)
    
    if not os.path.isfile(wordlist):
        print(f"Parol fayli topilmadi: {wordlist}")
        sys.exit(1)
    
    result = crack_wifi(cap_file, wordlist)
    
    if result:
        print("Parol muvaffaqiyatli topildi!")
    else:
        print("Parol topilmadi!")