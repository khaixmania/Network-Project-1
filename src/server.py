#!/usr/bin/env python3
import socket
import argparse
import os
import sys
import select
import srtp
import time
import random

# Arguments we type into the terminal, we just fetch them with this function
def parse_args():
    parser = argparse.ArgumentParser(description="Serveur baseline UDP avec support IPv6 ")
    parser.add_argument("host", help="Adresse IPv6 (::1)")
    parser.add_argument("port", type=int, help="Port UDP (8080)")
    parser.add_argument("--root", default=".", help="Dossier racine (\".\" par défaut)")
    return parser.parse_args()

def main():
    args = parse_args()
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        # On bind le socket à l'adresse et au port spécifiés
        sock.bind((args.host, args.port))
        print(f"[*] Serveur UDP en écoute sur [{args.host}]:{args.port}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Erreur de bind: {e}", file=sys.stderr)
        sys.exit(1) # On quitte le programme en cas d'erreur de bind (provenance du TP - TCP)

    # On boucle à l'infini pour recevoir les messages des clients
    while True:
        try:
            data, client_addr = sock.recvfrom(2048)
            #On décode le paquet reçu avec TA fonction
            ptype, window, seqnum, timestamp, payload = srtp.decode_packet(data)
            
            # Si c'est une requête de données (Le GET du client)
            if ptype == srtp.PTYPE_DATA:
                message = payload.decode('ascii', errors='ignore')
                print(f"[<] Requête reçue de {client_addr} (seq={seqnum}): {message}", file=sys.stderr)
                
                if message.startswith("GET "):
                    # On extrait le nom du fichier (on enlève le "/" au début)
                    filename = message.split(" ")[1].lstrip("/")
                    filepath = os.path.join(args.root, filename)
                    
                    if os.path.exists(filepath) and os.path.isfile(filepath):
                        # On coupe le fichier en morceaux de 1024 bytes au max (= 1 paquet)
                        f_list = [] # exemple: [b"segment1", b"segment2", b"segment3", b""]
                        with open(filepath, 'rb') as f:
                            while True:
                                segment= f.read(1024) 
                                if not segment: # Fin du fichier
                                    break
                                f_list.append(segment)
                        
                        # On ajoute le paquet EOF (Payload vide) obligatoire !
                        f_list.append(b"")
                        print(f"[*] Fichier trouvé : découpé en {len(f_list)} paquets.", file=sys.stderr)
                        
                        # On implémente la logique de sliding window pour envoyer les paquets au client
                        unack = 0 # L'index du plus vieux paquet non acquitté
                        next_unack = 0 # L'index du prochain paquet à envoyer
                        cli_win = window # La fenêtre annoncée par le client (ex: 63)
                        timer_start = None
                        #Calcul du RTO avec la formule de Jacobson/Karels
                        alpha = 0.125
                        beta = 0.25
                        est_mean_rtt = None
                        est_std_dev = None
                        TIMEOUT = 0.5 #Timer initial 
                        send_times = {} # Dictionnaire pour stocker l'heure d'envoi {seq: time}
                        retransmitted_seq = set() # Pour Karn/Partridge

                        # Tant qu'on n'a pas reçu d'ACK pour le tout dernier paquet
                        while unack < len(f_list):
                            while next_unack < unack + cli_win and next_unack < len(f_list): 
                                seq = next_unack % 2048 
                                packet = srtp.encode_packet(srtp.PTYPE_DATA, 63, seq, timestamp, f_list[next_unack])
                                
                                sock.sendto(packet, client_addr)
                                # Karn/Partridge : On ne met à jour le timer que pour les paquets envoyés pour la première fois
                                #si c'est la première fois qu'on envoie ce paquet, on stocke son heure d'envoi, sinon c'est une retransmission
                                if seq not in send_times:
                                    send_times[seq] = time.time() # Premier envoi
                                else:
                                    retransmitted_seq.add(seq) # C'est une retransmission

                                # Si on vient d'envoyer le premier paquet de la fenêtre, on lance le chrono
                                if unack == next_unack:
                                    timer_start = time.time()

                                next_unack += 1
                                
                            # B. Écoute des ACKs
                            readable, _, _ = select.select([sock], [], [], 0.05)
                            
                            if readable:
                                ack_data, _ = sock.recvfrom(2048)
                                ack_ptype, ack_window, ack_seq, ack_timestamp, ack_payload = srtp.decode_packet(ack_data)
                                
                                if ack_ptype == srtp.PTYPE_ACK:
                                    cli_win = ack_window
                                    #Calcul du RTO avec Karn/Partridge
                                    # Si l'ACK correspond à un paquet qui n'a pas été retransmis, on peut mettre à jour les estimations de RTT
                                    acked_seq = (ack_seq - 1) % 2048
                                    if acked_seq in send_times and acked_seq not in retransmitted_seq:
                                        rtt_measured = time.time() - send_times[acked_seq]
                                        
                                        if est_mean_rtt is None:
                                            est_mean_rtt = rtt_measured
                                            est_std_dev = rtt_measured / 2
                                        else:
                                            # Formules exactes du cours
                                            est_std_dev = (1 - beta) * est_std_dev + beta * abs(rtt_measured - est_mean_rtt)
                                            est_mean_rtt = (1 - alpha) * est_mean_rtt + alpha * rtt_measured
                                            
                                        # timer = mean(rtt) + 4*std_dev(rtt)
                                        TIMEOUT = est_mean_rtt + 4 * est_std_dev
                                        # On met un RTO minimum de 0.1s (sinon le select() à 0.05s plante)
                                        TIMEOUT = max(0.1, TIMEOUT)
                                        print(f"[RTT] Seq {acked_seq} | RTT réel: {rtt_measured:.4f}s -> Nouveau RTO: {TIMEOUT:.4f}s", file=sys.stderr)
                                        del send_times[acked_seq]
                                    
                                    # Gestion de l'ACK cumulatif
                                    for i in range(unack + 1, next_unack + 1):
                                        if (i % 2048) == ack_seq:
                                            unack = i # On fait glisser la base de la fenêtre
                                            if unack < next_unack:
                                                timer_start = time.time() # On relance le chrono
                                            else:
                                                timer_start = None # Tout est validé, on coupe le chrono
                                            break
                            else:
                                # C. LE TIMEOUT : Si le chrono expire
                                if timer_start and (time.time() - timer_start > TIMEOUT):
                                    print(f"[!] TIMEOUT expiré (RTO={TIMEOUT:.3f}s) sur seq={unack % 2048} !", file=sys.stderr)
                                    
                                    # Karn/Partridge : On marque toute la fenêtre courante comme retransmise
                                    for i in range(unack, next_unack):
                                        retransmitted_seq.add(i % 2048)
                                        
                                    timer_start = time.time()
                                    next_unack = unack # On repart de la base de la fenêtre pour retransmettre les paquets non acquittés
                                    
                        print(f"[*] Transfert terminé avec succès pour {filename} !", file=sys.stderr)

                    else:
                        error_packet = srtp.encode_packet(srtp.PTYPE_DATA, 63, 0, timestamp, b"")
                        sock.sendto(error_packet, client_addr)

        except Exception as e:
            print(f"[!] Erreur inattendue: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()