#!/usr/bin/env python3
import zlib
import struct

PTYPE_DATA = 1
PTYPE_ACK = 2
PTYPE_SACK = 3

def encode_first_packet(ptype, window, length, seqnum):
    ptype = (ptype & 0x3) #2bits
    window = (window & 0x3F) #6bits
    length = (length & 0x1FFF) #13bits donc c'est 8191 bytes max, mais on limitera à 1024 bytes dans notre code
    seqnum = (seqnum & 0x7FF) #11bits 
    header = ((ptype << 30) | (window << 24) | (length << 11) | seqnum) #32 bits au total
    return struct.pack('!I', header) #! pour Big-Endian,I pour unsigned int (4 bytes)

def encode_packet(ptype, window, seqnum, timestamp, payload=b""):
    payload_len = len(payload)
    if payload_len > 1024:
        raise ValueError(f"Le payload ({payload_len} bytes) fait plus grand que 1024 bytes")
    first_packet = encode_first_packet(ptype, window, payload_len, seqnum) #first packet de 4 bytes (32 bits)
    timestamp_packet = struct.pack('!I', timestamp) #4bytes
    
    header = first_packet + timestamp_packet #total 8 bytes
    crc1_packet = zlib.crc32(header) #CRC1 est calculé sur les 8 bytes du header et nous renvoie un entier de 4 bytes (32 bits)
    
    packet = header + struct.pack('!I', crc1_packet) #8 bytes du header + 4 bytes du CRC1 = 12
    #Si on a un payload, c'est bon, on l'ajoute et on calcule le CRC2 sur le payload
    #Sinon, on n'ajoute pas de payload et pas de CRC2
    if payload_len > 0:
        packet += payload ##En Python, on peut faire des += sur les bytes pour les concatener
        crc2_packet = zlib.crc32(payload) #CRC2 est calculé sur le payload et nous renvoie un entier de 4 bytes (32 bits)
        packet += struct.pack('!I', crc2_packet)
    return packet

def decode_packet(received_packet):
    if len(received_packet) < 12:
        raise ValueError("Le paquet est trop petit (moins de 12 bytes)")

    header = received_packet[:8] #8 bytes du header (first packet + timestamp)
    crc1_received = struct.unpack('!I', received_packet[8:12])[0] #juste après les 8, sur 4 bytes
    
    if crc1_received != zlib.crc32(header): #Calcul du crc1 sur les bytes du header, si c'est pas égal, alors le header est corrupted
        raise ValueError("CRC1 invalide car le header est corrompu")

    first_packet = struct.unpack('!I', received_packet[:4])[0]
    ptype = (first_packet >> 30) & 0x3

    #Erreur si c'est autre que 1, 2 ou 3
    if ptype not in [PTYPE_DATA, PTYPE_ACK, PTYPE_SACK]:
        raise ValueError(f"Le type de paquet n'est pas bon: {ptype}")
    
    window = (first_packet >> 24) & 0x3F
    length = (first_packet >> 11) & 0x1FFF
    seqnum = (first_packet & 0x7FF)

    #Ne pas depasser le seuil de 1024 bytes de payload, sinon erreur
    if length > 1024:
        raise ValueError(f"Longueur ({length}) dépasse 1024 bytes")

    timestamp = struct.unpack('!I', received_packet[4:8])[0]

    payload = b""
    if length > 0:
        expected_len = (12 + length + 4) #12 bytes du header + payload + 4 bytes du CRC2
        if len(received_packet) < expected_len:
            raise ValueError("Le paquet est tronqué (payload ou CRC2 est manquant)")
            
        payload = received_packet[12:12+length]
        crc2_received = struct.unpack('!I', received_packet[12+length:expected_len])[0]
        
        if crc2_received != zlib.crc32(payload):
            raise ValueError("CRC2 invalide car le payload est corrompu")

    return ptype, window, seqnum, timestamp, payload

if __name__ == "__main__":
    print("Tests srtp.py\n")

    # TEST 1 : Paquet DATA contenant un payload basique
    print("[Test 1] Encodage/Décodage d'un paquet DATA normal")
    payload_1 = b"Hello C'Hokayy!"
    packet_1 = encode_packet(PTYPE_DATA, 63, 10, 12345, payload_1)
    print(f"-> Paquet généré ({len(packet_1)} octets).")
    dec_ptype, dec_win, dec_seq, dec_time, dec_payload = decode_packet(packet_1)
    assert dec_payload == payload_1, "Erreur: Le payload décodé est différent !"
    print("-> Succès: Le paquet a été encodé et décodé parfaitement.\n")

    # TEST 2 : Paquet ACK sans payload (Le paquet le plus court possible)
    print("[Test 2] Encodage/Décodage d'un paquet ACK (vide)")
    packet_2 = encode_packet(PTYPE_ACK, 63, 11, 12346, b"")
    print(f"-> Paquet généré ({len(packet_2)} octets).")
    assert len(packet_2) == 12, "Erreur: Un ACK vide doit faire exactement 12 octets !"
    print("-> Succès: Le paquet ACK fait bien 12 octets (En-tête + CRC1).\n")

    # TEST 3 : La limite absolue (1024 octets)
    print("[Test 3] Paquet avec la limite maximum de 1024 octets de payload")
    payload_3 = b"A" * 1024
    packet_3 = encode_packet(PTYPE_DATA, 63, 12, 12347, payload_3)
    print(f"-> Paquet généré ({len(packet_3)} octets au total).")
    assert len(packet_3) == 1040, "Erreur: 1024 (payload) + 12 (en-tête) + 4 (CRC2) = 1040 octets."
    print("-> Succès: La limite de 1024 octets est bien gérée.\n")

    # TEST 4 : Dépassement de la limite (Doit crasher proprement)
    print("[Test 4] Rejet d'un payload trop grand (1025 octets)")
    payload_4 = b"B" * 1025
    try:
        encode_packet(PTYPE_DATA, 63, 13, 12348, payload_4)
        print("-> ERREUR: Le code aurait dû planter !")
    except ValueError as e:
        print(f"-> Succès: Dépassement bloqué avec le message : '{e}'\n")

    # TEST 5 : Simulation de corruption du réseau (Test du CRC)
    print("[Test 5] Détection d'un paquet corrompu")
    # On prend le paquet_1 parfait et on modifie délibérément un octet de l'en-tête
    corrupted_packet = bytearray(packet_1)
    corrupted_packet[0] = 0xFF
    try:
        decode_packet(corrupted_packet)
        print("-> ERREUR: Le code a accepté un paquet corrompu !")
    except ValueError as e:
        print(f"-> Succès: La corruption a été stoppée par le CRC. Message : '{e}'\n")
