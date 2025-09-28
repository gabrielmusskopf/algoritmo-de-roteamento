#!/bin/bash

# Topolgia:
#
#           (Rede A: 10.1.0.0/24)
#        R1 --------------------- R2
#        |                        |
# (Rede D: 10.4.0.0/24)    (Rede B: 10.2.0.0/24)
#        |                        |
#        R4 -------------------- R3 ----- (Rede Dummy: 192.168.3.0/24)
#           (Rede C: 10.3.0.0/24)

echo "=== Limpando configurações de rede antigas... ==="
sudo ip netns del ns1 2>/dev/null
sudo ip netns del ns2 2>/dev/null
sudo ip netns del ns3 2>/dev/null
sudo ip netns del ns4 2>/dev/null
echo "Limpeza concluída."

echo "=== Criando Network Namespaces 'ns1' a 'ns4'... ==="
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip netns add ns3
sudo ip netns add ns4

# Função auxiliar para criar um link veth entre dois namespaces
create_link() {
  NS1=$1
  IP1=$2
  NS2=$3
  IP2=$4
  VETH1=veth-${NS1}-${NS2}
  VETH2=veth-${NS2}-${NS1}
  
  echo "--- Criando link: ${NS1}(${IP1}) <--> ${NS2}(${IP2})"
  sudo ip link add ${VETH1} type veth peer name ${VETH2}
  sudo ip link set ${VETH1} netns ${NS1}
  sudo ip link set ${VETH2} netns ${NS2}
  sudo ip netns exec ${NS1} ip addr add ${IP1}/24 dev ${VETH1}
  sudo ip netns exec ${NS1} ip link set dev ${VETH1} up
  sudo ip netns exec ${NS2} ip addr add ${IP2}/24 dev ${VETH2}
  sudo ip netns exec ${NS2} ip link set dev ${VETH2} up
}

# Criar os links do "quadrado"
create_link ns1 10.1.0.1 ns2 10.1.0.2  # Rede A
create_link ns2 10.2.0.2 ns3 10.2.0.3  # Rede B
create_link ns3 10.3.0.3 ns4 10.3.0.4  # Rede C
create_link ns4 10.4.0.4 ns1 10.4.0.1  # Rede D

echo "=== Habilitando IP Forwarding em todos os roteadores... ==="
sudo ip netns exec ns1 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ns2 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ns3 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ns4 sysctl -w net.ipv4.ip_forward=1

echo "=== Adicionando rede dummy ao Roteador 3 (ns3)... ==="
sudo ip netns exec ns3 ip link add dummy0 type dummy
sudo ip netns exec ns3 ip link set dev dummy0 up
sudo ip netns exec ns3 ip addr add 192.168.3.1/24 dev dummy0

# Ativar interfaces de loopback
sudo ip netns exec ns1 ip link set dev lo up
sudo ip netns exec ns2 ip link set dev lo up
sudo ip netns exec ns3 ip link set dev lo up
sudo ip netns exec ns4 ip link set dev lo up

# --- Execução dos Processos ---
echo "=== Executando os roteadores em seus namespaces ==="
echo "--> Para iniciar os roteadores, execute o código no respectivo namespace. Exemplo:"
echo "    sudo ip netns exec ns1 python3 router.py 10.1.1.1 --interfaces veth-r1,10.1.1.1/24; exec bash"
echo "    sudo ip netns exec ns2 python3 router.py 10.1.1.2 --interfaces veth-r2a,10.1.1.2/24 veth-r2b,10.1.2.1/24; exec bash"
echo "    sudo ip netns exec ns3 python3 router.py 10.1.2.2 --interfaces veth-r3,10.1.2.2/24 dummy0,192.168.3.1/24; exec bash"

echo
echo "Para limpar o ambiente depois, execute: sudo bash cleanup_network.sh"

echo
echo "Sugestão: adicione delay em um dos caminhos de R1 para R3 para observar a troca de rotas. Exemplo:"
echo "    sudo ip netns exec ns2 tc qdisc add dev veth-ns2-ns3 root netem delay 500ms loss 20%"
echo "    ou"
echo "    sudo ip netns exec ns4 tc qdisc add dev veth-ns4-ns1 root netem delay 500ms loss 20%"
echo "E para remover:"
echo "    sudo ip netns exec ns2 tc qdisc del dev veth-ns2-ns3 root"
echo "    ou"
echo "    sudo ip netns exec ns4 tc qdisc del dev veth-ns4-ns1 root"

# --- Cria o script de limpeza ---
cat << EOF > cleanup_network.sh
#!/bin/bash
echo "Limpando network namespaces..."
sudo ip netns del ns1
sudo ip netns del ns2
sudo ip netns del ns3
# As veths são removidas automaticamente com os namespaces
echo "Ambiente limpo."
rm cleanup_network.sh
EOF
chmod +x cleanup_network.sh
