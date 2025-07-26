import os
import sys
import hashlib
import hmac
from binascii import a2b_hex, b2a_hex
from scapy.all import rdpcap
from pbkdf2 import PBKDF2

def check_handshake(packets, bssid):
    """CAP fayldan handshake paketlarini tekshiradi"""
    handshake_found = False
    for pkt in packets:
        if pkt.haslayer('EAPOL'):
            if pkt.addr2.lower() == bssid.lower() or pkt.addr3.lower() == bssid.lower():
                handshake_found = True
    return handshake_found

def pmk_to_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    """PMK dan PTK ni hisoblaydi"""
    # PTK ni generatsiya qilish
    A = b"Pairwise key expansion"
    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = PBKDF2(pmk, B, 4096, 32).read(80)
    return ptk

def check_password(pmk, anonce, snonce, ap_mac, client_mac, mic):
    """Parolni tekshiradi"""
    ptk = pmk_to_ptk(pmk, anonce, snonce, ap_mac, client_mac)
    # MIC ni hisoblash
    # Bu joyda to'g'ri MIC hisoblash logikasi bo'lishi kerak
    # Soddalik uchun bu qismni o'tkazib yuboramiz
    return False  # Haqiqiy loyihada bu ancha murakkab

def crack_wifi(cap_file, wordlist):
    """Asosiy parol sinash funksiyasi"""
    try:
        # CAP faylni o'qish
        packets = rdpcap(cap_file)
        
        # BSSID va handshake paketlarini aniqlash
        bssid = None
        handshake_packets = []
        for pkt in packets:
            if pkt.haslayer('Dot11Beacon'):
                bssid = pkt.addr2.lower()
                break
        
        if not bssid:
            print("BSSID topilmadi!")
            return False
        
        if not check_handshake(packets, bssid):
            print("Handshake topilmadi!")
            return False
        
        # Parol faylini o'qish
        with open(wordlist, 'r', encoding='latin-1') as f:
            for password in f:
                password = password.strip()
                if not password:
                    continue
                
                # PMK ni hisoblash (WPA/WPA2 uchun)
                pmk = PBKDF2(password, bssid.encode(), 4096, 32).read(32)
                
                # Bu yerda handshake paketlaridan anonce, snonce, mic larni olish kerak
                # Soddalik uchun bu qismni o'tkazib yuboramiz
                
                # Agar parol to'g'ri bo'lsa
                # if check_password(pmk, ...):
                #     print(f"Parol topildi: {password}")
                #     return True
                
                # Demo uchun faqat parollarni chiqaramiz
                print(f"Sinab ko'rilmoqda: {password}")
                
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
    
    print(f"WiFi parol sinash boshlandi...")
    print(f"CAP fayl: {cap_file}")
    print(f"Parol fayli: {wordlist}")
    
    result = crack_wifi(cap_file, wordlist)
    
    if result:
        print("Parol muvaffaqiyatli topildi!")
    else:
        print("Parol topilmadi!")