from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import struct
import socket
import logging

# Configura el logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("STUNServer")

# Constantes para CLASSIC-STUN (RFC 3489)
STUN_PORT = 3478  # Puerto principal
ALTERNATE_PORT = 3479  # Puerto alternativo
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
MAPPED_ADDRESS = 0x0001
RESPONSE_ADDRESS = 0x0002
CHANGE_REQUEST = 0x0003
SOURCE_ADDRESS = 0x0004
CHANGED_ADDRESS = 0x0005
XOR_MAPPED_ADDRESS = 0x8020  # No estándar, pero usado en algunos servidores CLASSIC-STUN
SERVER = 0x8022  # Identificador del servidor

class STUNServer(DatagramProtocol):
    def __init__(self, alternate_port=None, server_ip="0.0.0.0", alternate_ip=None):
        self.alternate_port = alternate_port
        self.server_ip = server_ip
        self.alternate_ip = alternate_ip or server_ip

    def datagramReceived(self, data, addr):
        logger.info(f"Received datagram from {addr}")

        if len(data) < 20:
            logger.error("Datagram too short")
            return

        # Desempaquetar cabecera
        msg_type, msg_length = struct.unpack("!HH", data[:4])
        transaction_id = data[4:20]

        if msg_type != BINDING_REQUEST:
            logger.error(f"Unsupported message type: {msg_type}")
            return

        # Parsear atributos
        attributes = self.parse_attributes(data[20:])

        # Crear Binding Response
        response = self.create_binding_response(addr, transaction_id)

        # Manejar RESPONSE-ADDRESS
        response_addr = attributes.get(RESPONSE_ADDRESS, addr)

        # Manejar CHANGE-REQUEST
        change_flags = attributes.get(CHANGE_REQUEST, 0)
        use_alternate = False
        if change_flags & 0x0004:  # CHANGE-IP
            if self.alternate_ip != self.server_ip:
                logger.info(f"Using alternate IP: {self.alternate_ip}")
                use_alternate = True
            else:
                logger.warning("CHANGE-IP requested but no alternate IP configured")
        if change_flags & 0x0002:  # CHANGE-PORT
            if self.alternate_port:
                logger.info(f"Using alternate port: {self.alternate_port}")
                use_alternate = True
            else:
                logger.warning("CHANGE-PORT requested but no alternate port configured")

        # Enviar respuesta desde puerto/IP alternativo si es necesario
        if use_alternate and self.alternate_port:
            reactor.listenUDP(self.alternate_port, STUNServer()).transport.write(response, response_addr)
        else:
            self.transport.write(response, response_addr)
        logger.info(f"Sent Binding Response to {response_addr}")

    def parse_attributes(self, attr_data):
        attributes = {}
        pos = 0
        while pos < len(attr_data):
            if len(attr_data) - pos < 4:
                break
            attr_type, attr_length = struct.unpack("!HH", attr_data[pos:pos+4])
            pos += 4
            value = attr_data[pos:pos+attr_length]
            pos += attr_length

            if attr_type == RESPONSE_ADDRESS:
                _, family, port = struct.unpack("!BBH", value[:4])
                ip = socket.inet_ntoa(value[4:])
                attributes[RESPONSE_ADDRESS] = (ip, port)
            elif attr_type == CHANGE_REQUEST:
                (flags,) = struct.unpack("!I", value)
                attributes[CHANGE_REQUEST] = flags

        return attributes

    def create_binding_response(self, addr, transaction_id):
        # IP y puerto del cliente
        client_ip = socket.inet_aton(addr[0])
        client_port = addr[1]

        # MAPPED-ADDRESS
        mapped_value = struct.pack("!BBH", 0x00, 0x01, client_port) + client_ip
        mapped_attr = struct.pack("!HH", MAPPED_ADDRESS, 8) + mapped_value

        # SOURCE-ADDRESS (IP/puerto del servidor)
        server_ip = socket.inet_aton(self.server_ip)
        source_value = struct.pack("!BBH", 0x00, 0x01, STUN_PORT) + server_ip
        source_attr = struct.pack("!HH", SOURCE_ADDRESS, 8) + source_value

        # CHANGED-ADDRESS (IP/puerto alternativo)
        changed_ip = socket.inet_aton(self.alternate_ip)
        changed_value = struct.pack("!BBH", 0x00, 0x01, self.alternate_port or STUN_PORT) + changed_ip
        changed_attr = struct.pack("!HH", CHANGED_ADDRESS, 8) + changed_value

        # XOR-MAPPED-ADDRESS (IP/puerto XOR con un valor fijo, común en CLASSIC-STUN)
        xor_ip = bytes(a ^ b for a, b in zip(client_ip, struct.pack("!I", 0x2112A442)))  # Magic cookie
        xor_value = struct.pack("!BBH", 0x00, 0x01, client_port ^ 0x2112) + xor_ip
        xor_attr = struct.pack("!HH", XOR_MAPPED_ADDRESS, 8) + xor_value

        # SERVER (nombre del servidor)
        server_name = "Fiveserver STUN v0.1"
        server_value = server_name.encode("utf-8")
        server_attr = struct.pack("!HH", SERVER, len(server_value)) + server_value

        # Longitud total
        msg_length = len(mapped_attr) + len(source_attr) + len(changed_attr) + len(xor_attr) + len(server_attr)

        # Cabecera
        header = struct.pack("!HH", BINDING_RESPONSE, msg_length) + transaction_id

        return header + mapped_attr + source_attr + changed_attr + xor_attr + server_attr

def start_stun_server():
    # Configura tu IP pública o local aquí
    server_ip = "195.26.248.178"  # Cambia a la IP de tu servidor
    alternate_ip = "195.26.248.178"  # Cambia si tienes una IP alternativa
    logger.info(f"Starting STUN server on {server_ip}:{STUN_PORT} with alternate {alternate_ip}:{ALTERNATE_PORT}")
    reactor.listenUDP(STUN_PORT, STUNServer(alternate_port=ALTERNATE_PORT, server_ip=server_ip, alternate_ip=alternate_ip))
    reactor.listenUDP(ALTERNATE_PORT, STUNServer(server_ip=server_ip, alternate_ip=alternate_ip))
