import time
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import argparse
import ipaddress

# TODO:
# Protocolo
# - [x] Criar tabela de roteamento com as interfaces fisicamente conectadas
# - [x] Propagar tabela de rotamento em broadcast nas interface conectadas
# - [x] Receber a tabela de roteamento dos vizinhos
# - [x] Atualizar a tabela de roteamento com as rotas recebidas
# - [x] Expirar rota após TTL
# Encaminhamento
# - [ ] Encaminhar um pacote de dado com base na métrica
# Kernel
# - [ ] Inserir rota na tabela do kernel
# - [ ] Remover rota da tabela do kernel
# Probes para latência e perda de pacote
# - [ ] Enviar probe para latência
# - [ ] Enviar probes para perda de pacote
# - [ ] Responder probes
# - [ ] Recalcular métrica da rota


@dataclass
class RouteEntry:
    """Representa uma única entrada na tabela de roteamento."""
    destination_network: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address
    metric: int
    outgoing_interface: str
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

            # Se a rota não existe ou a nova rota tem uma métrica melhor, atualiza.
            if destination not in self._routes or new_route.metric < self._routes[destination].metric:
                print(f"[RoutingTable] Updating route to {destination} via {new_route.next_hop}")
                self._routes[destination] = new_route
            # Se a rota veio do mesmo vizinho, apenas renova o timestamp
            elif self._routes[destination].next_hop == new_route.next_hop:
                self._routes[destination].timestamp = new_route.timestamp

    def get_route(self, destination: ipaddress.IPv4Network) -> Optional[RouteEntry]:
        """Retorna a rota para uma rede específica."""
        with self._lock:
            return self._routes.get(destination)

    def get_all_routes(self) -> List[RouteEntry]:
        """Retorna uma cópia de todas as rotas ativas."""
        with self._lock:
            return list(self._routes.values())

    def remove_expired_routes(self, timeout: int):
        """Varre a tabela e remove rotas que não são atualizadas há algum tempo."""
        with self._lock:
            expired_destinations = [
                dest for dest, route in self._routes.items() if route.is_expired(timeout)
            ]
            for dest in expired_destinations:
                print(f"[RoutingTable] Route to {dest} expired. Removing.")
                del self._routes[dest]

    def get_printable_string(self) -> str:
        with self._lock:
            if not self._routes:
                return "Routing Table is empty."

            routes_copy = list(self._routes.values())

        header = "Destination          | Next Hop        | Metric | Interface\n"
        divider = "---------------------+-----------------+--------+----------\n"
        rows = [
            f"{str(route.destination_network):<20} | {str(route.next_hop):<15} | {route.metric:<6} | {route.outgoing_interface}\n"
            for route in routes_copy
        ]
        return header + divider + "".join(rows)


@dataclass
class NetworkInterface:
    """Representa uma interface de rede física/virtual da máquina."""
    name: str
    ip_interface: ipaddress.IPv4Interface
    mac_address: str
    state: str  # "UP" or "DOWN"


class ProtocolHandler:
    """Responsável por toda a comunicação de rede do protocolo de roteamento."""

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

        self.sock.bind(('', self.protocol_port))

    def create_update_packet(self) -> bytes:
        """Cria um pacote com as rotas da tabela para anunciar aos vizinhos."""
        routes = self.routing_table.get_all_routes()
        payload = ";".join([f"{r.destination_network},{r.metric}" for r in routes])
        return payload.encode('utf-8')

    def parse_incoming_packet(self, data: bytes, source_ip: str):
        """Interpreta um pacote recebido e atualiza a tabela de roteamento."""
        payload = data.decode('utf-8')
        received_routes = payload.split(';')

        for route_str in received_routes:
            try:
                dest_str, metric_str = route_str.split(',')
                new_entry = RouteEntry(
                    destination_network=ipaddress.IPv4Network(dest_str),
                    next_hop=ipaddress.IPv4Address(source_ip),
                    metric=int(metric_str) + 1,  # Métrica do vizinho + 1 (custo do salto)
                    outgoing_interface="TODO: determine interface"  # Determinar por qual interface o pacote chegou
                )
                self.routing_table.add_or_update_route(new_entry)
            except (ValueError, IndexError):
                print(f"[ProtocolHandler] Malformed route data received from {source_ip}: {route_str}")

    def gossip_table(self, interfaces: List[NetworkInterface]):
        """Envia pacotes de descoberta ou métricas para vizinhos."""
        # A implementação depende da sua estratégia de métricas (latência, etc.)
        # Exemplo: Enviar um pacote para o endereço de broadcast da rede local.
        update_packet = self.create_update_packet()

        for iface in interfaces:
            if iface.state == "UP":
                broadcast_address = str(iface.ip_interface.network.broadcast_address)
                print(f"[ProtocolHandler] Sending routing update via {iface.name} to {broadcast_address}")
                self.sock.sendto(update_packet, (broadcast_address, self.protocol_port))

    def listen_for_packets(self):
        """Loop principal para escutar pacotes de outros roteadores."""
        print("[ProtocolHandler] Listening for routing packets...")
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                source_ip = addr[0]
                print(f"[ProtocolHandler] Received packet from {source_ip}")
                self.parse_incoming_packet(data, source_ip)
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
        """
        Processa as definições de interface passadas via argumento de linha de comando.
        """
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
