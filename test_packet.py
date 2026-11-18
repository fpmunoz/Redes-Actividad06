import router

packet_in_bytes = b'\x7f\x00\x00\x01\x22\xb1\x0a\x00\x2a\x00\x00\x00\x00\x00\x00\x00\x04\x00hola'

# SIN TTL
# ---------- PASO 4 ----------
#IP_packet_v1 = packet_in_bytes

#parsed_IP_packet = router.parse_packet(IP_packet_v1)
#print("parsed:", parsed_IP_packet)

#IP_packet_v2 = router.create_packet(parsed_IP_packet)
#print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))



# CON TTL (ACTIVIDAD 6)
# ---------- PASO 1 ----------
#IP_packet_v1 = packet_in_bytes

#parsed_IP_packet = router.parse_packet(IP_packet_v1)
#print("parsed:", parsed_IP_packet)

#IP_packet_v2_str = router.create_packet(parsed_IP_packet)
#IP_packet_v2 = IP_packet_v2_str.encode()
#print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2_str))


# ---------- PASO 1 ----------
msg = b"---------- MENSAJE - MUY - LARGO ----- HELLO - WORLD ----------"
msg_dict = {"ip": "127.0.0.1",
            "port": 8881,
            "ttl": 10,
            "id": 42,
            "offset": 0,
            "flag": 0,
            "payload": msg}

IP_packet_v1 = router.create_packet(msg_dict)
print("Paquete original (largo {} bytes): {}".format(len(IP_packet_v1), IP_packet_v1))

MTU = 23
fragment_list = router.fragment_ip_packet(IP_packet_v1, MTU)
print("\nfragmentos generados: MTU = {}".format(MTU))

for i, f in enumerate(fragment_list):
    print("Fragmento {}: {}".format(i, router.parse_packet(f)))

IP_packet_v2 = router.reassemble_ip_packet(fragment_list)
print("IP_packet_v1 == IP_packet_v2 ? {}".format(IP_packet_v1 == IP_packet_v2))