#!/usr/bin/env python3
import socket
import argparse
import sys
import srtp
from urllib.parse import urlparse

def parse_args():
    parser = argparse.ArgumentParser(description="Client baseline UDP avec support IPv6")
    parser.add_argument("--save", default="llm.model", help="Fichier qu'on veut sauvegarder (\"llm.model\" par défaut)")
    parser.add_argument("url", help="URL du serveur (ex: udp://[::1]:8080)")
    return parser.parse_args()

def main():
    args = parse_args()
    #Décode l'url pour fetch hostname, port et path
    parsed_url = urlparse(args.url)
    hostname = parsed_url.hostname
    port = (parsed_url.port or 8080)
    path = (parsed_url.path or "/")

    if not hostname:
        print("[!] URL invalide", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Cible -> {hostname}:{port}", file=sys.stderr)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    # On set un timer de 5 secondes pour ne pas bloquer indéfiniment sur recvfrom
    sock.settimeout(5)
    target_addr = (hostname, port)

    try:
        # 1. Encodage et envoi de la requête HTTP 0.9 en SRTP
        load = f"GET {path}".encode('ascii')
        request_packet = srtp.encode_packet(srtp.PTYPE_DATA, window=63, seqnum=0, timestamp=1234, payload=load)
        sock.sendto(request_packet, target_addr)
        expected_seq = 0
        print(f"[>] Requête SRTP envoyée : GET {path}", file=sys.stderr)

        # 2. Boucle de réception du fichier
        with open(args.save, 'wb') as f:
            while True:
                data, _ = sock.recvfrom(2048)
                ptype, win, seq, ts, payload = srtp.decode_packet(data)

                if ptype == srtp.PTYPE_DATA:
                    # On n'accepte le paquet QUE si c'est exactement celui qu'on attend !
                    if seq == expected_seq:
                        if len(payload) == 0:
                            print("[<] Signal EOF reçu. Fin du fichier.", file=sys.stderr)
                            expected_seq = (expected_seq + 1) % 2048
                            ack_pkt = srtp.encode_packet(srtp.PTYPE_ACK, 63, expected_seq, ts, b"")
                            sock.sendto(ack_pkt, target_addr)
                            break 
                        
                        # C'est le bon paquet, on l'écrit !
                        print(f"[<] Paquet reçu DANS L'ORDRE : seq={seq}, size={len(payload)}", file=sys.stderr)
                        f.write(payload)
                        expected_seq = (expected_seq + 1) % 2048
                    else:
                        print(f"[!] Paquet HORS ORDRE (Reçu {seq}, Attendu {expected_seq}). Rejeté.", file=sys.stderr)

                    # Quoi qu'il arrive, on renvoie un ACK cumulatif (ce qu'on attend actuellement)
                    ack_pkt = srtp.encode_packet(srtp.PTYPE_ACK, 63, expected_seq, ts, b"")
                    sock.sendto(ack_pkt, target_addr)

        print(f"[*] Transfert réussi ! Fichier sauvegardé dans : {args.save}", file=sys.stderr)

    except socket.timeout:
        print("[!] Timeout : Le serveur ne répond plus.", file=sys.stderr)
    except Exception as e:
        print(f"[!] Erreur : {e}", file=sys.stderr)
    finally:
        sock.close()

if __name__ == "__main__":
    main()