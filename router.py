import time
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import argparse
import ipaddress
import subprocess

# Protocolo:
# +-------------+-----------+-------+
# | Versão (1B) | Tipo (1B) | Dados |
# +-------------+-----------+-------+
#
# Os bytes de dados sempre trafegam convertidos com utf-8.
#
# Tipos:
# PACKET_TYPE_UPDATE
#   Pacote com os dados das rotas que não foram recebidas por essa interface. Dados são
#   ip,custo,latência separados por ;. Exemplo 192.168.1.0,2,15;10.10.1.0,3,12. Esse pacote instrui
#   o roteador a atualizar sua tabela de roteamento, se necessário. Não espera nenhuma resposta.
#
# PACKET_TYPE_METRIC_PROBE_REQUEST
#   Pacotes para medição das métricas. Dados são o timestamp. Espera uma resposta
#   PACKET_TYPE_METRIC_PROBE_REPLY.
#
# PACKET_TYPE_METRIC_PROBE_REPLY
#   Resposta ao pacote de PACKET_TYPE_METRIC_PROBE_REQUEST. Dados são o timestamp atual.

# TODO:
# Protocolo
# - [x] Criar tabela de roteamento com as interfaces fisicamente conectadas
# - [x] Propagar tabela de rotamento em broadcast nas interface conectadas
# - [x] Receber a tabela de roteamento dos vizinhos
# - [x] Atualizar a tabela de roteamento com as rotas recebidas
# - [x] Expirar rota após TTL
# - [x] Split horizon
# Encaminhamento
# - [ ] Encaminhar um pacote de dado com base na métrica
# Kernel
# - [x] Inserir rota na tabela do kernel
# - [x] Remover rota da tabela do kernel
# Probes para latência e perda de pacote
# - [ ] Enviar probe para latência
# - [ ] Enviar probes para perda de pacote
# - [ ] Responder probes
# - [ ] Recalcular métrica da rota

try:
    # Tenta acessar o atributo para ver se ele existe. Atributo só foi adicionado na versão 3.12,
    # então para versões antigas é preciso atribuir manualmente.
    # https://docs.python.org/3/library/socket.html
    socket.IP_PKTINFO
except AttributeError:
    # Se não existir, definir com o valor padrão do Linux
    # https://github.com/torvalds/linux/blob/f975f08c2e899ae2484407d7bba6bb7f8b6d9d40/include/uapi/linux/in.h#L108
    socket.IP_PKTINFO = 8


@dataclass
class RouteEntry:
    """Representa uma única entrada na tabela de roteamento."""
    destination_network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address
    metric: int
    outgoing_interface: str
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def __str__(self):
        return f"Dest: {self.destination_network}, NextHop: {self.next_hop}, Metric: {self.metric}, Iface: {self.outgoing_interface}"

    def is_expired(self, timeout_seconds: int) -> bool:
        """Verifica se a rota expirou com base no seu timestamp."""
        return self.metric != 0 and (time.time() - self.timestamp) > timeout_seconds


class RoutingTable:
    """Gerencia todas as rotas conhecidas pelo roteador."""

    def __init__(self):
        self._routes: Dict[ipaddress.IPv4Network, RouteEntry] = {}
        self._lock = threading.Lock()

    def add_or_update_route(self, new_route: RouteEntry):
        """Adiciona uma nova rota ou atualiza uma existente se a nova for melhor (métrica menor)."""
        with self._lock:
            destination = new_route.destination_network
            latency_str = "inf" if new_route.latency_ms == float('inf') else f"{1000 * new_route.latency_ms:.2f}ms"

            if destination not in self._routes:
                print(f"[RoutingTable] Adding route to {destination} via {new_route.next_hop} with metric {new_route.metric} latency {latency_str}")
                self._routes[destination] = new_route
                self.add_kernel_route(
                    destination=str(new_route.destination_network),
                    gateway=str(new_route.next_hop)
                )

            elif new_route.metric < self._routes[destination].metric:
                print(f"[RoutingTable] Updating route to {destination} via {new_route.next_hop} with metric {new_route.metric} latency {latency_str} due to lower metric")
                self._routes[destination] = new_route
                self.add_kernel_route(
                    destination=str(new_route.destination_network),
                    gateway=str(new_route.next_hop)
                )

            elif new_route.latency_ms < self._routes[destination].latency_ms:
                print(f"[RoutingTable] Updating route to {destination} via {new_route.next_hop} with metric {new_route.metric} latency {latency_str} due to lower latency")
                self._routes[destination] = new_route
                self.add_kernel_route(
                    destination=str(new_route.destination_network),
                    gateway=str(new_route.next_hop)
                )

            # Se a rota veio do mesmo vizinho, apenas renova o timestamp
            elif self._routes[destination].next_hop == new_route.next_hop:
                print(f"[RoutingTable] Updating route timestamp to {destination} via {new_route.next_hop}")
                self._routes[destination].timestamp = new_route.timestamp

    def get_route(self, destination: ipaddress.IPv4Network) -> Optional[RouteEntry]:
        """Retorna a rota para uma rede específica."""
        with self._lock:
            return self._routes.get(destination)

    def get_all_routes(self) -> List[RouteEntry]:
        """Retorna uma cópia de todas as rotas ativas."""
        with self._lock:
            return list(self._routes.values())

    def get_direct_neighbors(self) -> List[str]:
        """Retorna uma lista de IPs de vizinhos diretamente conectados (métrica > 0)."""
        with self._lock:
            return list(str(route.next_hop) for route in self._routes.values() if route.metric > 0)

    def remove_expired_routes(self, timeout: int):
        """Varre a tabela e remove rotas que não são atualizadas há algum tempo."""
        with self._lock:
            expired_routes = [
                route for route in self._routes.values() if route.is_expired(timeout)
            ]
            for expired_route in expired_routes:
                dest = expired_route.destination_network
                print(f"[RoutingTable] Route to {dest} expired. Removing.")
                del self._routes[dest]

                self.del_kernel_route(
                    destination=str(expired_route.destination_network),
                    gateway=str(expired_route.next_hop)
                )

    def add_kernel_route(self, destination: str, gateway: str):
        """Adiciona uma rota na tabela do kernel usando o comando 'ip'."""
        if gateway == "0.0.0.0":
            return

        print(f"[Kernel] Adding route {destination} via {gateway} to kernel routing table")
        command = ["ip", "route", "add", destination, "via", gateway, "2>/dev/null"]
        print(f"[Kernel] { ' '.join(command) }")

        subprocess.run(command, check=False)

    def del_kernel_route(self, destination: str, gateway: str):
        """Remove uma rota da tabela do kernel usando o comando 'ip'."""
        if gateway == "0.0.0.0":
            return

        print(f"[Kernel] Removing route {destination} via {gateway} from kernel routing table")
        command = ["ip", "route", "del", destination, "via", gateway, "2>/dev/null"]
        print(f"[Kernel] { ' '.join(command) }")

        subprocess.run(command, check=False)

    def get_printable_string(self) -> str:
        with self._lock:
            if not self._routes:
                return "Routing Table is empty."

            routes_copy = list(self._routes.values())

        header = "Destination          | Next Hop        | Metric | Latency (ms) | Interface\n"
        divider = "---------------------+-----------------+--------+--------------+----------\n"
        rows = [
            f"{str(route.destination_network):<20} | {str(route.next_hop):<15} | {route.metric:<6} | {1000 * route.latency_ms:<12.2f} | {route.outgoing_interface}\n"
            for route in routes_copy
        ]
        return header + divider + "".join(rows)


@dataclass
class NetworkInterface:
    """Representa uma interface de rede física/virtual da máquina."""
    name: str
    ip_interface: ipaddress.IPv4Interface
    mac_address: str
    state: str  # "UP" ou "DOWN"
    # TODO: atualizar estado da interface com base no kernel


class ProtocolHandler:
    """Responsável por toda a comunicação de rede do protocolo de roteamento."""
    PROTOCOL_VERSION = 1
    HEADER_SIZE = 2

    # Tipos de Pacote
    PACKET_TYPE_UPDATE = 1
    PACKET_TYPE_METRIC_PROBE_REQUEST = 2
    PACKET_TYPE_METRIC_PROBE_REPLY = 3

    def __init__(self, router_id: ipaddress.IPv4Address, routing_table: RoutingTable):
        self.router_id = router_id
        self.routing_table = routing_table
        self.protocol_port = 50000

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # O envio/recebimento via broadcast funcionou somente com o bind em todas as interfaces
        # ('', ou 0.0.0.0). Essa opção informa ao kernel que a porta pode ser utilizada por n
        # processos, quando esta no estádo de TIME_WAIT
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # Pede ao kernel informações sobre a interface recebida. Usado para o split horizon
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
        self.sock.bind(('', self.protocol_port))

        self.neighbor_latency: Dict[str, float] = {}

    def _create_header(self, packet_type: int) -> bytes:
        """Cria o cabeçalho binário de 2 bytes para um pacote."""
        return struct.pack('!BB', self.PROTOCOL_VERSION, packet_type)

    def _handle_routing_update(self, data: bytes, source_ip: str, incoming_interface_name: str):
        """Interpreta um pacote de atualização de tabelas."""
        payload = data.decode('utf-8')
        received_routes = payload.split(';')

        latency_to_neighbor = self.neighbor_latency.get(source_ip, float('inf'))

        for route_str in received_routes:
            try:
                dest_str, metric_str, latency_str = route_str.split(',')
                total_latency = latency_to_neighbor + float(latency_str)

                print(f"[ProtocolHandler] {source_ip} send route {dest_str} with metric {metric_str}")
                new_entry = RouteEntry(
                    destination_network=ipaddress.IPv4Network(dest_str),
                    next_hop=ipaddress.IPv4Address(source_ip),
                    metric=int(metric_str) + 1,
                    latency_ms=total_latency,
                    outgoing_interface=incoming_interface_name
                )
                self.routing_table.add_or_update_route(new_entry)
            except (ValueError, IndexError):
                print(f"[ProtocolHandler] Malformed route data received from {source_ip}: {route_str}")

    def _handle_probe_request(self, data: bytes, source_ip: str, incoming_interface_name: str):
        """Interpreta um pacote de requisição de probe."""
        payload_str = str(time.time())
        payload_bytes = payload_str.encode('utf-8')

        header = self._create_header(self.PACKET_TYPE_METRIC_PROBE_REPLY)
        full_packet = header + payload_bytes

        print(f"[ProtocolHandler] Sending a probe reply to {source_ip}")
        self.sock.sendto(full_packet, (source_ip, self.protocol_port))

    def _handle_probe_reply(self, data: bytes, source_ip: str, incoming_interface_name: str):
        """Interpreta um pacote de resposta ao probe."""
        received_timestamp = float(data.decode('utf-8'))
        rtt = time.time() - received_timestamp
        self.neighbor_latency[source_ip] = rtt

    def gossip_table(self, interfaces: List[NetworkInterface]):
        """Envia a tabela de rotas para vizinhos."""
        all_routes = self.routing_table.get_all_routes()

        for iface in interfaces:
            if iface.state == "UP":
                routes_to_send = [
                    route for route in all_routes if route.outgoing_interface != iface.name
                ]

                if not routes_to_send:
                    continue

                # rede/máscara,metrica,latencia
                payload_str = ";".join([f"{r.destination_network},{r.metric},{r.latency_ms}" for r in routes_to_send])
                payload_bytes = payload_str.encode('utf-8')

                header = self._create_header(self.PACKET_TYPE_UPDATE)
                full_packet = header + payload_bytes

                print(header.decode('utf-8'))
                print(full_packet.decode('utf-8'))

                broadcast_address = str(iface.ip_interface.network.broadcast_address)
                print(f"[ProtocolHandler] Sending routing update via {iface.name} to {broadcast_address}")
                self.sock.sendto(full_packet, (broadcast_address, self.protocol_port))

    def probe_request(self):
        """Envia um pacote para as medições de latência."""
        for neighbor in self.routing_table.get_direct_neighbors():
            payload_str = str(time.time())
            payload_bytes = payload_str.encode('utf-8')

            header = self._create_header(self.PACKET_TYPE_METRIC_PROBE_REQUEST)
            full_packet = header + payload_bytes

            print(f"[ProtocolHandler] Sending a probe request to {neighbor}")
            self.sock.sendto(full_packet, (neighbor, self.protocol_port))

    def listen_for_packets(self):
        """Loop principal para escutar pacotes de outros roteadores."""
        print("[ProtocolHandler] Listening for routing packets...")
        if_map = {index: name for index, name in socket.if_nameindex()}

        while True:
            try:
                data, ancdata, flags, addr = self.sock.recvmsg(1024, 1024)
                source_ip = addr[0]
                if ipaddress.IPv4Address(source_ip) == self.router_id:
                    continue

                incoming_interface_name = "unknown"
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == socket.IPPROTO_IP and cmsg_type == socket.IP_PKTINFO:
                        # Ler um inteiro sem sinal ("I") do buffer
                        if_index = struct.unpack_from("I", cmsg_data)[0]
                        incoming_interface_name = if_map.get(if_index, "unknown")
                        break

                version, packet_type = struct.unpack_from('!BB', data)
                payload_bytes = data[self.HEADER_SIZE:]

                if version != self.PROTOCOL_VERSION:
                    print("[ProtocolHandler] Message discarted, unknown version")
                    continue

                if packet_type == self.PACKET_TYPE_UPDATE:
                    print(f"[ProtocolHandler] Received update from {source_ip} via {incoming_interface_name} interface")
                    self._handle_routing_update(payload_bytes, source_ip, incoming_interface_name)

                elif packet_type == self.PACKET_TYPE_METRIC_PROBE_REQUEST:
                    print(f"[ProtocolHandler] Received probe request from {source_ip} via {incoming_interface_name} interface")
                    self._handle_probe_request(payload_bytes, source_ip, incoming_interface_name)

                elif packet_type == self.PACKET_TYPE_METRIC_PROBE_REPLY:
                    print(f"[ProtocolHandler] Received probe reply from {source_ip} via {incoming_interface_name} interface")
                    self._handle_probe_reply(payload_bytes, source_ip, incoming_interface_name)

                else:
                    print(f"[ProtocolHandler] Received unknown packet {packet_type} from {source_ip} via {incoming_interface_name}")

            except OSError as e:
                print(f"[ProtocolHandler] Socket error: {e}")
                break


class Router:
    """A classe principal que gerencia o daemon de roteamento."""

    def __init__(self, router_id: str):
        self.router_id = ipaddress.IPv4Address(router_id)
        self.routing_table = RoutingTable()
        self.interfaces: List[NetworkInterface] = []
        self.protocol_handler = ProtocolHandler(self.router_id, self.routing_table)

        # Timers de configuração do protocolo, em segundos
        self.update_interval = 10
        self.route_timeout = 30

    def discover_interfaces(self, interface_definitions: List[str]):
        """Processa as definições de interface passadas via argumento de linha de comando."""
        print("[Router] Configuring interfaces from command line arguments...")

        if not interface_definitions:
            print("[Router] ERROR: No interfaces provided. Exiting.")
            exit(1)

        for iface_def in interface_definitions:
            try:
                # O formato esperado é "nome,ip/prefixo"
                name, ip_str = iface_def.split(',')

                iface = NetworkInterface(
                    name=name,
                    ip_interface=ipaddress.IPv4Interface(ip_str),
                    # MAC address pode ser um placeholder, pois não é usado na lógica de roteamento IP
                    mac_address="00:00:00:00:00:00",
                    state="UP"
                )
                self.interfaces.append(iface)
                print(f"[Router] Configured interface: {name} with IP {iface.ip_interface}")

                # Adiciona a rede diretamente conectada à tabela de roteamento com métrica 0
                connected_route = RouteEntry(
                    destination_network=iface.ip_interface.network,
                    next_hop=ipaddress.IPv4Address("0.0.0.0"),
                    metric=0,
                    latency_ms=0.0,
                    outgoing_interface=iface.name
                )
                self.routing_table.add_or_update_route(connected_route)

            except ValueError:
                print(f"[Router] ERROR: Malformed interface definition: '{iface_def}'. "
                      "Expected format: name,ip/prefix. Exiting.")
                exit(1)

    def start(self):
        """Inicia todas as operações do roteador."""
        # Iniciar o listener de pacotes em uma thread separada para não bloquear o resto
        listener_thread = threading.Thread(target=self.protocol_handler.listen_for_packets, daemon=True)
        listener_thread.start()

        print("[Router] Starting periodic tasks...")
        while True:
            try:
                self.routing_table.remove_expired_routes(self.route_timeout)
                self.protocol_handler.gossip_table(self.interfaces)
                self.protocol_handler.probe_request()

                print("\n--- Current Routing Table ---")
                print(self.routing_table.get_printable_string())

                time.sleep(self.update_interval)

            except KeyboardInterrupt:
                print("[Router] Shutting down...")
                self.protocol_handler.sock.close()
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inicia um daemon de roteamento customizado.")

    parser.add_argument(
        "router_id",
        help="O endereço IP principal que serve como ID único para este roteador."
    )
    parser.add_argument(
        "--interfaces",
        required=True,
        nargs='+',
        help="Define uma ou mais interfaces diretamente conectadas. "
             "Formato: nome,ip/prefixo. Ex: --interfaces veth0,10.10.0.1/24 veth1,10.20.0.1/24"
    )

    args = parser.parse_args()

    try:
        my_router = Router(router_id=args.router_id)
        my_router.discover_interfaces(interface_definitions=args.interfaces)
        my_router.start()

    except ipaddress.AddressValueError:
        print(f"ERRO: O router_id '{args.router_id}' não é um endereço IPv4 válido.")
        exit(1)
