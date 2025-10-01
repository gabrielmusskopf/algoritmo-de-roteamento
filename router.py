import time
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import argparse
import ipaddress
import subprocess
import secrets
import random

# Introduz uma probabilidade de não responder o pacote de medição de perda para fins didáticos
PACKET_LOSS_PROBABILITY = 0.0

LOG_LEVELS = {"error": 1, "warn": 2, "info": 3, "debug": 4, "trace": 5}
LOG_LEVEL = LOG_LEVELS.get("debug")


def is_level_enabled(level: int) -> bool:
    global LOG_LEVEL
    return level <= LOG_LEVEL


def is_info_enabled() -> bool:
    value = LOG_LEVELS.get("info")
    return is_level_enabled(value)


def log(level: str, message: str, tag: str = None) -> None:
    value = LOG_LEVELS.get(level, 4)
    level = f"{level}:"
    tag = f"[{tag}] " if tag else ""
    if is_level_enabled(value):
        print(f"{level:<6} {tag}{message}")


def trace(message: str, tag: str = None) -> None:
    log("trace", message, tag)


def debug(message: str, tag: str = None) -> None:
    log("debug", message, tag)


def info(message: str, tag: str = None) -> None:
    log("info", message, tag)


def warn(message: str, tag: str = None) -> None:
    log("warn", message, tag)


def error(message: str, tag: str = None) -> None:
    log("error", message, tag)


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
    loss_percent: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def __str__(self):
        return f"Dest: {self.destination_network}, NextHop: {self.next_hop}, Iface: {self.outgoing_interface}, Metric: {self.metric}, Latency: {self.latency_ms:.1f}, Loss: {self.loss_percent}"

    def is_expired(self, timeout_seconds: int) -> bool:
        """Verifica se a rota expirou com base no seu timestamp."""
        return self.metric != 0 and (time.time() - self.timestamp) > timeout_seconds


class RoutingTable:
    """Gerencia todas as rotas conhecidas pelo roteador."""

    def __init__(self):
        self._routes: Dict[ipaddress.IPv4Network, RouteEntry] = {}
        self._lock = threading.Lock()

    def _is_new_route_better(self, existing_route: RouteEntry, new_route: RouteEntry) -> bool:
        """Define a função de custo para determinar a melhor rota."""
        # Métrica (contagem de saltos) é o mais importante
        if new_route.metric < existing_route.metric:
            return True
        if new_route.metric > existing_route.metric:
            return False

        # Se a métrica for igual, a perda de pacotes é o desempate
        if new_route.loss_percent < existing_route.loss_percent:
            return True
        if new_route.loss_percent > existing_route.loss_percent:
            return False

        # Se a perda também for igual, a latência é o desempate
        if new_route.latency_ms < existing_route.latency_ms:
            return True

        return False

    def add_or_update_route(self, new_route: RouteEntry):
        """Adiciona uma nova rota ou atualiza uma existente se a nova for melhor (métrica menor)."""
        with self._lock:
            destination = new_route.destination_network

            # A rota para este destino ainda não existe. Simplesmente adiciona.
            if destination not in self._routes:
                info(f"New route to {destination} via {new_route.next_hop}", tag="RoutingTable")
                self._routes[destination] = new_route
                self.add_kernel_route(str(destination), str(new_route.next_hop))
                return

            existing_route = self._routes[destination]

            # A atualização vem do mesmo vizinho que a rota atual.
            # Aceitar sempre a atualização, seja ela melhor ou pior.
            if existing_route.next_hop == new_route.next_hop:
                info(f"Updating metrics to {destination} via {new_route.next_hop}", tag="RoutingTable")
                self._routes[destination] = new_route
                return

            # A atualização vem de um vizinho diferente.
            # Comparar para ver se o novo caminho é melhor.
            if self._is_new_route_better(existing_route, new_route):
                info(f"New best path to {destination} via {new_route.next_hop}", tag="RoutingTable")
                debug(f"Next hop: {existing_route.next_hop} --> {new_route.next_hop}\n"
                      f"\tMetric: {existing_route.metric} --> {new_route.metric}\n"
                      f"\tLatency: {existing_route.latency_ms:.1f} --> {new_route.latency_ms:.1f}\n"
                      f"\tLoss: {existing_route.loss_percent} --> {new_route.loss_percent}")
                self.del_kernel_route(str(destination), str(existing_route.next_hop))
                self.add_kernel_route(str(destination), str(new_route.next_hop))
                self._routes[destination] = new_route

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
            distinct_neighbors = {str(route.next_hop) for route in self._routes.values() if route.metric > 0}
            return list(distinct_neighbors)

    def remove_expired_routes(self, timeout: int):
        """Varre a tabela e remove rotas que não são atualizadas há algum tempo."""
        with self._lock:
            expired_routes = [
                route for route in self._routes.values() if route.is_expired(timeout)
            ]
            for expired_route in expired_routes:
                dest = expired_route.destination_network
                info(f"Route to {dest} expired. Removing.", tag="RoutingTable")
                del self._routes[dest]

                self.del_kernel_route(
                    destination=str(expired_route.destination_network),
                    gateway=str(expired_route.next_hop)
                )

    def add_kernel_route(self, destination: str, gateway: str):
        """Adiciona uma rota na tabela do kernel usando o comando 'ip'."""
        if gateway == "0.0.0.0":
            return

        info(f"Adding route {destination} via {gateway} to kernel routing table", tag="Kernel")
        command = ["ip", "route", "add", destination, "via", gateway]
        debug(f"{ ' '.join(command) }", tag="Kernel")

        subprocess.run(command, check=False, stderr=subprocess.DEVNULL)

    def del_kernel_route(self, destination: str, gateway: str):
        """Remove uma rota da tabela do kernel usando o comando 'ip'."""
        if gateway == "0.0.0.0":
            return

        info(f"Removing route {destination} via {gateway} from kernel routing table", tag="Kernel")
        command = ["ip", "route", "del", destination, "via", gateway]
        debug(f"{ ' '.join(command) }", tag="Kernel")

        subprocess.run(command, check=False, stderr=subprocess.DEVNULL)

    def get_printable_string(self) -> str:
        with self._lock:
            if not self._routes:
                return "Routing Table is empty."

            routes_copy = list(self._routes.values())

        header = "Destination          | Next Hop        | Metric | Latency (ms) | Loss (%) | Interface\n"
        divider = "---------------------+-----------------+--------+--------------+----------+----------\n"
        rows = [
            f"{str(route.destination_network):<20} | {str(route.next_hop):<15} | {route.metric:<6} | {route.latency_ms:<12.1f} | {route.loss_percent:<8} | {route.outgoing_interface}\n"
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
    PACKET_TYPE_LATENCY_REQUEST = 2
    PACKET_TYPE_LATENCY_REPLY = 3
    PACKET_TYPE_LOSS_REQUEST = 4
    PACKET_TYPE_LOSS_REPLY = 5

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

        self.neighbor_latency: Dict[str, float] = {}  # {ip_vizinho: latencia_em_ms}
        self.neighbor_loss: Dict[str, float] = {}

        self._pending_probes: Dict[bytes, float] = {}  # {token: send_timestamp}
        self._loss_session_id = 0
        self._pending_loss_tests: Dict[int, Dict] = {}  # {session_id: {sent_time, count, received: set, dest}}
        self._probes_lock = threading.Lock()

    def _create_header(self, packet_type: int) -> bytes:
        """Cria o cabeçalho binário de 2 bytes para um pacote."""
        return struct.pack('!BB', self.PROTOCOL_VERSION, packet_type)

    def _handle_routing_update(self, data: bytes, source_ip: str, incoming_interface_name: str):
        """Interpreta um pacote de atualização de tabelas."""
        info(f"Received update from {source_ip} via {incoming_interface_name} interface", tag="ProtocolHandler-Gossip")

        payload = data.decode('utf-8')
        received_routes = payload.split(';')

        latency_to_neighbor_ms = self.neighbor_latency.get(source_ip, float('inf'))
        loss_to_neighbor = self.neighbor_loss.get(source_ip, 100.0)

        for route_str in received_routes:
            try:
                debug(f"{source_ip} send {route_str}", tag="ProtocolHandler-Gossip")
                dest_str, metric_str, latency_str, loss_str = route_str.split(',')

                total_latency = latency_to_neighbor_ms + float(latency_str)
                path_loss = max(loss_to_neighbor, float(loss_str))

                debug(f"{source_ip} send route {dest_str} with metric {metric_str} latency {total_latency:.1f} loss {path_loss}", tag="ProtocolHandler-Gossip")
                new_entry = RouteEntry(
                    destination_network=ipaddress.IPv4Network(dest_str),
                    next_hop=ipaddress.IPv4Address(source_ip),
                    metric=int(metric_str) + 1,
                    latency_ms=total_latency,
                    loss_percent=path_loss,
                    outgoing_interface=incoming_interface_name
                )
                self.routing_table.add_or_update_route(new_entry)
            except (ValueError, IndexError):
                warn(f"Malformed route data received from {source_ip}: {route_str}", tag="ProtocolHandler-Gossip")

    def _handle_latency_request(self, data: bytes, source_ip: str):
        """Interpreta um pacote de requisição de probe."""
        trace(f"Received latency probe request from {source_ip}", tag="ProtocolHandler-Latency")

        token = data
        header = self._create_header(self.PACKET_TYPE_LATENCY_REPLY)
        full_packet = header + token

        trace(f"Sending a latency probe reply {token.hex()} to {source_ip}", tag="ProtocolHandler-Latency")
        self.sock.sendto(full_packet, (source_ip, self.protocol_port))

    def _handle_latency_reply(self, data: bytes, source_ip: str):
        """Interpreta um pacote de resposta ao probe."""

        token = data
        with self._probes_lock:
            if token in self._pending_probes:
                start_time = self._pending_probes.pop(token)
                rtt = (time.time() - start_time) * 1000
                self.neighbor_latency[source_ip] = rtt
                trace(f"Received latency probe reply {token.hex()} from {source_ip}. RTT: {rtt:.2f} ms", tag="ProtocolHandler-Latency")
            else:
                warn(f"Received unexpected latency probe reply {token.hex()} from {source_ip}", tag="ProtocolHandler-Latency")

    def _handle_loss_request(self, data: bytes, source_ip: str):
        """Interpreta um pacote de requisição ao probe de perda de pacote."""
        trace(f"Received packet loss probe request from {source_ip}", tag="ProtocolHandler-Loss")

        # Intruduzir uma probabilidade de falha para simular perda de pacotes
        if random.random() < PACKET_LOSS_PROBABILITY:
            debug("Simulatin packet loss", tag="ProtocolHandler-Loss")
            return

        session_id, seq_num = struct.unpack_from('!II', data)
        reply_payload = struct.pack('!II', session_id, seq_num)

        header = self._create_header(self.PACKET_TYPE_LOSS_REPLY)
        full_packet = header + reply_payload

        trace(f"Sending a packet loss probe reply #{seq_num} to {source_ip} (session {session_id})", tag="ProtocolHandler-Loss")
        self.sock.sendto(full_packet, (source_ip, self.protocol_port))

    def _handle_loss_reply(self, data: bytes, source_ip: str):
        """Interpreta um pacote de resposta ao probe de perda de pacote."""
        session_id, seq_num = struct.unpack_from('!II', data)
        trace(f"Received packet loss probe reply #{seq_num} from {source_ip} (session {session_id})", tag="ProtocolHandler-Loss")

        with self._probes_lock:
            if session_id in self._pending_loss_tests:
                self._pending_loss_tests[session_id]["received"].add(seq_num)

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

                # rede/máscara,metrica,latencia,perda
                payload_str = ";".join([f"{r.destination_network},{r.metric},{r.latency_ms},{r.loss_percent}" for r in routes_to_send])
                payload_bytes = payload_str.encode('utf-8')

                header = self._create_header(self.PACKET_TYPE_UPDATE)
                full_packet = header + payload_bytes

                broadcast_address = str(iface.ip_interface.network.broadcast_address)
                info(f"Sending routing update via {iface.name} to {broadcast_address}", tag="ProtocolHandler-Gossip")
                self.sock.sendto(full_packet, (broadcast_address, self.protocol_port))

    def send_latency_probe(self):
        """Envia um pacote para as medições de latência."""
        for neighbor in self.routing_table.get_direct_neighbors():
            token = secrets.token_bytes(1)
            with self._probes_lock:
                # Armazena o momento do envio para calcular o RTT depois
                self._pending_probes[token] = time.time()

            header = self._create_header(self.PACKET_TYPE_LATENCY_REQUEST)
            full_packet = header + token

            info(f"Sending a probe request {token.hex()} to {neighbor}", tag="ProtocolHandler-Latency")
            self.sock.sendto(full_packet, (neighbor, self.protocol_port))

    def start_loss_probe(self, count: int = 10):
        """Inicia uma sessão de teste de perda de pacotes enviando vários probes."""
        for neighbor in self.routing_table.get_direct_neighbors():
            with self._probes_lock:
                self._loss_session_id += 1
                session_id = self._loss_session_id
                self._pending_loss_tests[session_id] = {
                    "sent_time": time.time(),
                    "count": count,
                    "received": set(),
                    "destination": neighbor
                }

            info(f"Starting packet loss test to {neighbor} (session #{session_id}, {count} packets)", tag="ProtocolHandler-Loss")
            # O payload do pacote de perda conterá o ID da sessão e o número do pacote na rajada
            for i in range(count):
                seq_num_in_session = i + 1
                payload_bytes = struct.pack('!II', session_id, seq_num_in_session)
                header = self._create_header(self.PACKET_TYPE_LOSS_REQUEST)
                full_packet = header + payload_bytes
                self.sock.sendto(full_packet, (neighbor, self.protocol_port))

    def check_loss_probe(self, timeout: float = 2.0):
        """Verifica se algum teste de perda de pacotes expirou e reporta o resultado."""
        with self._probes_lock:
            for session_id in list(self._pending_loss_tests.keys()):
                session = self._pending_loss_tests[session_id]
                if time.time() - session["sent_time"] > timeout:
                    sent_count = session["count"]
                    received_count = len(session["received"])
                    loss_count = sent_count - received_count
                    loss_percent = (loss_count / sent_count) * 100 if sent_count > 0 else 0
                    destination = session['destination']

                    info(f"\n--- Packet loss test result ---\n"
                         f"Destination: {destination} (session #{session_id})\n"
                         f"  - Sent:   {sent_count}\n"
                         f"  - Received:  {received_count}\n"
                         f"  - Lost:   {loss_count} ({loss_percent:.1f}%)\n"
                         f"--------------------------------------------")

                    self.neighbor_loss[destination] = loss_percent
                    del self._pending_loss_tests[session_id]

    def cleanup_expired_latency_probes(self, timeout: float = 2.0):
        """Varre e remove os probes pendentes que expiraram (não receberam resposta)."""
        with self._probes_lock:
            current_time = time.time()
            expired_tokens = [
                token for token, start_time in self._pending_probes.items()
                if current_time - start_time > timeout
            ]

            for token in expired_tokens:
                del self._pending_probes[token]
                info(f"Latency probe {token.hex()} has expired.", tag="ProtocolHandler-Latency")
                print()

    def listen_for_packets(self):
        """Loop principal para escutar pacotes de outros roteadores."""
        info("Listening for routing packets...", tag="ProtocolHandler")
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
                    warn("Message discarted, unknown version", tag="ProtocolHandler")
                    continue

                if packet_type == self.PACKET_TYPE_UPDATE:
                    self._handle_routing_update(payload_bytes, source_ip, incoming_interface_name)

                elif packet_type == self.PACKET_TYPE_LATENCY_REQUEST:
                    self._handle_latency_request(payload_bytes, source_ip)

                elif packet_type == self.PACKET_TYPE_LATENCY_REPLY:
                    self._handle_latency_reply(payload_bytes, source_ip)

                elif packet_type == self.PACKET_TYPE_LOSS_REQUEST:
                    self._handle_loss_request(payload_bytes, source_ip)

                elif packet_type == self.PACKET_TYPE_LOSS_REPLY:
                    self._handle_loss_reply(payload_bytes, source_ip)

                else:
                    error(f"Received unknown packet {packet_type} from {source_ip} via {incoming_interface_name}", tag="ProtocolHandler")

            except OSError as e:
                error(f"Socket error: {e}", tag="ProtocolHandler")
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
        info("Configuring interfaces from command line arguments...", tag="Router")

        if not interface_definitions:
            error("No interfaces provided. Exiting.", tag="Router")
            exit(1)

        for iface_def in interface_definitions:
            try:
                # O formato esperado é "nome,ip/prefixo"
                name, ip_str = iface_def.split(',')

                iface = NetworkInterface(
                    name=name,
                    ip_interface=ipaddress.IPv4Interface(ip_str),
                    mac_address="00:00:00:00:00:00",  # placeholder
                    state="UP"
                )
                self.interfaces.append(iface)
                info(f"Configured interface: {name} with IP {iface.ip_interface}", tag="Router")

                connected_route = RouteEntry(
                    destination_network=iface.ip_interface.network,
                    next_hop=ipaddress.IPv4Address("0.0.0.0"),
                    metric=0,
                    latency_ms=0.0,
                    outgoing_interface=iface.name
                )
                self.routing_table.add_or_update_route(connected_route)

            except ValueError:
                error(f"Malformed interface definition: '{iface_def}'. "
                      "Expected format: name,ip/prefix. Exiting.", tag="Router")
                exit(1)

    def start(self):
        """Inicia todas as operações do roteador."""
        listener_thread = threading.Thread(target=self.protocol_handler.listen_for_packets, daemon=True)
        listener_thread.start()

        info("Starting periodic tasks...", tag="Router")
        while True:
            try:
                self.routing_table.remove_expired_routes(self.route_timeout)
                self.protocol_handler.gossip_table(self.interfaces)
                self.protocol_handler.send_latency_probe()
                self.protocol_handler.start_loss_probe()
                self.protocol_handler.cleanup_expired_latency_probes()
                self.protocol_handler.check_loss_probe()

                if is_info_enabled():
                    print("\n--- Current Routing Table ---\n"
                          f"{self.routing_table.get_printable_string()}")

                time.sleep(self.update_interval)

            except KeyboardInterrupt:
                info("Shutting down...", tag="Router")
                self.protocol_handler.sock.close()
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inicia um daemon de roteamento customizado.")

    parser.add_argument(
        "router_id",
        help="O endereço IP principal que serve como ID único para este roteador."
    )
    parser.add_argument(
        "--level",
        help="Nível de log",
        # choices=list(LOG_LEVELS.keys()),
        default="info"
    )
    parser.add_argument(
        "--interfaces",
        required=True,
        nargs='+',
        help="Define uma ou mais interfaces diretamente conectadas. "
             "Formato: nome,ip/prefixo. Ex: --interfaces veth0,10.10.0.1/24 veth1,10.20.0.1/24"
    )

    args = parser.parse_args()

    info(f"Nível de log: {args.level}")
    LOG_LEVEL = LOG_LEVELS.get(args.level)

    try:
        my_router = Router(router_id=args.router_id)
        my_router.discover_interfaces(interface_definitions=args.interfaces)
        my_router.start()

    except ipaddress.AddressValueError:
        error(f"O router_id '{args.router_id}' não é um endereço IPv4 válido.")
        exit(1)
