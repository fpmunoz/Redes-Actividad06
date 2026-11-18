import sys
import socket
import router

def main():
    # si viene con ttl se tienen 7 parametros
    if len(sys.argv) not in (6, 7, 8):
        sys.exit(1)
        
    ip_final = sys.argv[1]
    puerto_final = int(sys.argv[2])
    file_msg = sys.argv[3]
    ip_envio = sys.argv[4]
    puerto_envio = int(sys.argv[5])

    if len(sys.argv) >= 7:
        ttl = int(sys.argv[6])
    else:
        ttl = 10

    if len(sys.argv) >= 8:
        packet_id = int(sys.argv[7])
    else:
        packet_id = 0

    # armamos el paquete
    packet_dict = {"ip": ip_final,
                   "port": puerto_final,
                   "ttl": ttl,
                   "id": packet_id,
                   "offset": 0,
                   "flag": 0,
                   "payload": file_msg.encode("utf-8")}
    
    ip_packet_bytes = router.create_packet(packet_dict)

    # socket no orientado a conexion, no asociado a ninguna direccion
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.sendto(ip_packet_bytes, (ip_envio, puerto_envio))

        print(f"Enviado a ({ip_envio}, {puerto_envio}) hacia ({ip_final}, {puerto_final})")
    finally:
        sock.close()
    
    
if __name__ == "__main__":
    main()