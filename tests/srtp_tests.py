#!/usr/bin/env python3
import sys
import os

# Permet d'importer srtp depuis le dossier src/ qui est juste au-dessus
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
import srtp

def run_tests():
    print("=== Lancement de la suite de tests SRTP ===\n")

    print("[Test 1] Encodage/Décodage normal (DATA)")
    payload_1 = b"Hello C'Hokayy!"
    packet_1 = srtp.encode_packet(srtp.PTYPE_DATA, 63, 10, 12345, payload_1)
    _, _, _, _, dec_payload = srtp.decode_packet(packet_1)
    assert dec_payload == payload_1

    print("[Test 2] Encodage/Décodage vide (ACK)")
    packet_2 = srtp.encode_packet(srtp.PTYPE_ACK, 63, 11, 12346, b"")
    assert len(packet_2) == 12

    print("[Test 3] Limite stricte de 1024 octets")
    packet_3 = srtp.encode_packet(srtp.PTYPE_DATA, 63, 12, 12347, b"A" * 1024)
    assert len(packet_3) == 1040

    print("[Test 4] Rejet si > 1024 octets")
    try:
        srtp.encode_packet(srtp.PTYPE_DATA, 63, 13, 12348, b"B" * 1025)
        print("-> ERREUR: Le code aurait dû planter !")
    except ValueError:
        print("Exception bien levée\n")

    print("[Test 5] Détection de corruption (CRC32)")
    corrupted_packet = bytearray(packet_1)
    corrupted_packet[0] = 0xFF 
    try:
        srtp.decode_packet(corrupted_packet)
        print("-> ERREUR: Paquet corrompu accepté !")
    except ValueError:
        print("Corruption détectée\n")


if __name__ == "__main__":
    run_tests()