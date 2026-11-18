import sys
import socket
import ipaddress

# variable global para check_routes
# diccionario para el indice de round robin
STATE_RR: dict[tuple, int] = {}


def parse_packet(ip_packet: bytes):
    # primeros 4 bytes son a.b.c.d.
    ip_bytes = ip_packet[0:4]

    ip_str = ""

    for b in ip_bytes:
        ip_str += str(b) + "."

    # a.b.c.d
    ip_str = ip_str[:-1]

    # dos bytes para el puerto como un int
    port_bytes = ip_packet[4:6]
    port_int = int.from_bytes(port_bytes, byteorder="big", signed=False)  # ayuda de gemini

    # ttl
    ttl_bytes = ip_packet[6]

    # nuevos parametros
    id_int = int.from_bytes(ip_packet[7:9], byteorder="big", signed=False)
    offset_int = int.from_bytes(ip_packet[9:13], byteorder="big", signed=False)
    size_int = int.from_bytes(ip_packet[13:17], byteorder="big", signed=False)
    flag_int = ip_packet[17]

    # el resto de los bytes es el mensaje (payload)
    remaining_bytes = ip_packet[18:(18+size_int)]

    parsed = {"ip": ip_str,
              "port": port_int,
              "ttl": ttl_bytes,
              "id": id_int,
              "offset": offset_int,
              "size": size_int,
              "flag": flag_int,
              "payload": remaining_bytes}

    return parsed


def create_packet(parsed_ip_packet: dict):
    # vemos el mensaje y su largo primero
    remaining = parsed_ip_packet["payload"]

    # si el mensaje esta en str lo pasamos a bytes
    if isinstance(remaining, str):
        remaining = remaining.encode("utf-8")

    size_val = len(remaining)

    # vemos los campos del header
    # pasamos a.b.c.d a un int
    oct = []

    for n in parsed_ip_packet["ip"].split("."):
        oct.append(int(n))

    # 4 bytes de ip y 2 de puerto
    ip_bytes = bytes(oct)
    port_bytes = parsed_ip_packet["port"].to_bytes(2, byteorder="big", signed=False)
    ttl_bytes = parsed_ip_packet["ttl"].to_bytes(1, byteorder="big", signed=False)

    # el resto de los parametros
    id_bytes = parsed_ip_packet["id"].to_bytes(2, byteorder="big", signed=False)
    offset_bytes = parsed_ip_packet["offset"].to_bytes(4, byteorder="big", signed=False)
    size_bytes = size_val.to_bytes(4, byteorder="big", signed=False)
    flag_bytes = parsed_ip_packet["flag"].to_bytes(1, byteorder="big", signed=False)
    
    return (ip_bytes + port_bytes + ttl_bytes + id_bytes + offset_bytes + size_bytes + flag_bytes + remaining)



def  carga_tablas_rutas(file_name):
    tabla = []

    with open(file_name, "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()

            # ignoramos lineas vacias y comentarios
            if not linea or linea.startswith("#"):
                continue

            parts = linea.split()
            mtu = int(parts[5])
            
            reglas = {"red_cidr": parts[0],
                      "puerto_inicial": int(parts[1]),
                      "puerto_final": int(parts[2]),
                      "next_hop_ip": parts[3],
                      "next_hop_port": int(parts[4]),
                      "mtu": mtu}

            tabla.append(reglas)

    return tabla


def check_routes(routes_file_name: str, destination_address: tuple[str, int], rrstate: dict = None)-> tuple[str, int]:
    # correccion/idea de gemini
    # ponemos el estados de round robin como parametro y luego toma el valor de la variable global
    if rrstate == None:
        rrstate = STATE_RR

    dest_ip_str, dest_port = destination_address
    dest_ip = ipaddress.ip_address(dest_ip_str)  # ayuda de gemini

    # lista de posibles rutas
    eq_routes = []

    with open(routes_file_name, "r", encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
        
            if not linea or linea.startswith("#"):
                continue

            parts = linea.split()
            red = ipaddress.ip_network(parts[0], strict=False)  # ayuda de gemini
            puerto_inicial = int(parts[1])
            puerto_final = int(parts[2])
            next_hop_ip = parts[3]
            next_hop_port = int(parts[4])
            mtu = int(parts[5])

            # la rutas solo es aceptada si pertenece a la red y el puerto esta en el rango
            if dest_ip in red and (puerto_inicial <= dest_port <= puerto_final):
                eq_routes.append((next_hop_ip, next_hop_port, mtu))

    if not eq_routes:
        return None

    # buscamos el indice de rutas en el diccionerio y sacamos su resto con respecto a la cantidad de rutas
    indice = rrstate.get(tuple(eq_routes), 0) % len(eq_routes)
    next_hop_ip, next_hop_port, mtu = eq_routes[indice]

    # guardamos el indice de la sigueinte ruta
    rrstate[tuple(eq_routes)] = (indice+1) % len(eq_routes)

    return (next_hop_ip, next_hop_port), mtu


def fragment_ip_packet(ip_packet, MTU):
    # el paquete cabe por el enlace
    if len(ip_packet) <= MTU:
        return [ip_packet]

    max_payload = MTU - 18  # header size = 18

    # el paquete no cabe por el enlace y debe fragmentarse
    parsed = parse_packet(ip_packet)
    payload = parsed["payload"]
    og_offset = parsed["offset"]
    og_flag = parsed["flag"]

    fragments = []

    for i in range(0, len(payload), max_payload):
        data = payload[i:(i+max_payload)]

        if (i + max_payload) >= len(payload):
            last_data = True
        else:
            last_data = False

        if last_data:
            flag = og_flag
        else:
            flag = 1

        # armamos nuevos paquetes por cada fragmento
        flag_dict = {"ip": parsed["ip"],
                     "port": parsed["port"],
                     "ttl": parsed["ttl"],
                     "id": parsed["id"],
                     "offset": og_offset + i,
                     "flag": flag,
                     "payload": data}

        fragments.append(create_packet(flag_dict))

    return fragments


def reassemble_ip_packet(fragment_list):
    if not fragment_list:
        return None

    # volvemos a parsear los fragmentos:
    parsed_frags = []

    for f in fragment_list:
        parsed_frags.append(parse_packet(f))

    # ordenamos la lista
    parsed_frags.sort(key=lambda f: f["offset"])  # ayuda de gemini

    if parsed_frags[0]["offset"] != 0:
        return None

    # revisamos que esten bien los fragmentos
    exp_offset = 0
    payload_data = []

    for f in parsed_frags:
        if f["offset"] == exp_offset:
            payload_data.append(f["payload"])
            exp_offset += f["size"]
        # fragmetnos duplicados se ignoran
        elif f["offset"] < exp_offset:
            continue
        # falta un argumento
        else: 
            return None

    if parsed_frags[-1]["flag"] != 0:
        return None

    full_payload = b"".join(payload_data)

    dict_fragments = {"ip": parsed_frags[0]["ip"],
                      "port": parsed_frags[0]["port"],
                      "ttl": parsed_frags[0]["ttl"],
                      "id": parsed_frags[0]["id"],
                      "offset": 0,
                      "flag": 0,
                      "payload": full_payload}

    return create_packet(dict_fragments)




def main():
    # 3 parametros
    if len(sys.argv) != 4:
        sys.exit(1)

    router_ip = sys.argv[1]
    router_puerto = int(sys.argv[2])
    file_router = sys.argv[3]
    dir_router = (router_ip, router_puerto)
    
    tabla_rutas = carga_tablas_rutas(file_router)

    # diccionario para los fragmentos de este route
    frag_buffer: dict[int, list[bytes]] = {}

    # socket no orientado a conexion asociado a la direccion del router
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(dir_router)

    print(f"Router iniciado en {dir_router}")
    print(f"Tablas de rutas desde '{file_router}': {tabla_rutas}\n")

    try:
        while True:
            # se bloquea hasta que recibe un paquete
            data, addr = sock.recvfrom(4096)
            parsed = parse_packet(data)

            # se acabo el ttl
            if parsed["ttl"] <= 0:
                print(f"Se recibió paquete {data} con TTL 0\n")
                continue

            dest_addr = (parsed['ip'], parsed['port'])

            # el mensaje es para el router actual si no se busca el siguiente
            if dest_addr == dir_router:
                packet_id = parsed["id"]

                # almacenamos el fragmento sin modificar
                if packet_id not in frag_buffer:
                    frag_buffer[packet_id] = []

                frag_buffer[packet_id].append(data)

                # rearmamos el paquete del fragmento
                reassembled_packet = reassemble_ip_packet(frag_buffer[packet_id])

                if reassembled_packet != None:
                    full_parsed = parse_packet(reassembled_packet)

                    msg = full_parsed["payload"].decode("utf-8", errors="replace")
                    print(msg)
            else:
                route = check_routes(file_router, dest_addr)

                if route != None:
                    dir_next_hop, mtu = route

                    parsed["ttl"] -= 1
                    new_data = create_packet(parsed)

                    fragments = fragment_ip_packet(new_data, mtu)

                    for f in fragments:
                        print(f"Redirigiendo paquete {f} con destino final {dest_addr} desde {dir_router} hacia {dir_next_hop}")

                        sock.sendto(f, dir_next_hop)
                else:
                    print(f"No hay rutas hacia {dest_addr} para paquete {data}")

    except KeyboardInterrupt:
        sock.close()
        print("\nApagando router...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()