#!/bin/bash

# O objetivo deste script é criar um laboratório de rede virtual em uma única máquina Linux para 
# testar um protocolo de roteamento customizado (implementado em router.py).
#
# O ambiente simula uma topologia de rede com três roteadores em série (R1 <--> R2 <--> R3), 
# permitindo a verificação da capacidade do protocolo de propagar rotas através de múltiplos 
# saltos (hops). 
#
# São utilizados namespaces distintos para simular um cenário mais próximo da realidade,
# onde cada roteador está isolado dos demais.
#
#  Topologia:
#
#  +----------+                           +----------+                           +----------+
#  |    R1    |     (Rede 10.1.1.0/24)    |    R2    |     (Rede 10.1.2.0/24)    |    R3    |
#  |   (ns1)  |  veth-r1 <----> veth-r2a  |   (ns2)  |  veth-r2b <----> veth-r3  |   (ns3)  |
#  +----------+                           +----------+                           +----------+
#  IP: 10.1.1.1                          IP 1: 10.1.1.2                          IP: 10.1.2.2
#                                        IP 2: 10.1.2.1                  Rede Dummy: 192.168.3.0/24
#
# Desenvolvido e testado em um Ubuntu 22.04

# --- Limpeza do Ambiente Anterior ---
echo "=== Limpando configurações de rede antigas... ==="
sudo ip link del veth-r1 2>/dev/null
sudo ip link del veth-r2a 2>/dev/null
sudo ip link del veth-r2b 2>/dev/null
sudo ip link del veth-r3 2>/dev/null
sudo ip netns del ns1 2>/dev/null
sudo ip netns del ns2 2>/dev/null
sudo ip netns del ns3 2>/dev/null
echo "Limpeza concluída."
echo

# --- Criação dos Namespaces ---
echo "=== Criando Network Namespaces 'ns1', 'ns2' e 'ns3'... ==="
sudo ip netns add ns1
sudo ip netns add ns2
sudo ip netns add ns3
echo

# --- Configuração do Link R1 <--> R2 (Rede 10.1.1.0/24) ---
echo "=== Configurando o link entre R1 e R2... ==="
sudo ip link add veth-r1 type veth peer name veth-r2a
# Mover as pontas do "cabo" para os namespaces corretos
sudo ip link set veth-r1 netns ns1
sudo ip link set veth-r2a netns ns2
# Configurar os IPs e ativar as interfaces dentro de cada namespace
sudo ip netns exec ns1 ip addr add 10.1.1.1/24 dev veth-r1
sudo ip netns exec ns1 ip link set dev veth-r1 up
sudo ip netns exec ns2 ip addr add 10.1.1.2/24 dev veth-r2a
sudo ip netns exec ns2 ip link set dev veth-r2a up
echo

# --- Configuração do Link R2 <--> R3 (Rede 10.1.2.0/24) ---
echo "=== Configurando o link entre R2 e R3... ==="
sudo ip link add veth-r2b type veth peer name veth-r3
# Mover as pontas do "cabo" para os namespaces corretos
sudo ip link set veth-r2b netns ns2
sudo ip link set veth-r3 netns ns3
# Configurar os IPs e ativar as interfaces
sudo ip netns exec ns2 ip addr add 10.1.2.1/24 dev veth-r2b
sudo ip netns exec ns2 ip link set dev veth-r2b up
sudo ip netns exec ns3 ip addr add 10.1.2.2/24 dev veth-r3
sudo ip netns exec ns3 ip link set dev veth-r3 up
echo

# --- Habilitar Roteamento em R2 (Passo Essencial!) ---
echo "=== Habilitando IP Forwarding no Roteador 2 (ns2)... ==="
sudo ip netns exec ns2 sysctl -w net.ipv4.ip_forward=1
echo

# --- Adicionar Rota Dummy em R1 ---
echo "=== Adicionando rede dummy 192.168.2.0/24 ao Roteador 2 (ns1)... ==="
sudo ip netns exec ns1 ip link add dummy0 type dummy
sudo ip netns exec ns1 ip link set dev dummy0 up
sudo ip netns exec ns1 ip addr add 192.168.2.1/24 dev dummy0
echo

# --- Adicionar Rota Dummy em R3 ---
echo "=== Adicionando rede dummy 192.168.3.0/24 ao Roteador 3 (ns3)... ==="
sudo ip netns exec ns3 ip link add dummy0 type dummy
sudo ip netns exec ns3 ip link set dev dummy0 up
sudo ip netns exec ns3 ip addr add 192.168.3.1/24 dev dummy0
echo

# --- Ativar interfaces de loopback (boa prática) ---
sudo ip netns exec ns1 ip link set dev lo up
sudo ip netns exec ns2 ip link set dev lo up
sudo ip netns exec ns3 ip link set dev lo up

# --- Execução dos Processos ---
echo "=== Executando os roteadores em seus namespaces ==="
echo "--> Para iniciar os roteadores, execute o código no respectivo namespace. Exemplo:"
echo "    sudo ip netns exec ns1 python3 router.py 10.1.1.1 --interfaces veth-r1,10.1.1.1/24; exec bash"
echo "    sudo ip netns exec ns2 python3 router.py 10.1.1.2 --interfaces veth-r2a,10.1.1.2/24 veth-r2b,10.1.2.1/24; exec bash"
echo "    sudo ip netns exec ns3 python3 router.py 10.1.2.2 --interfaces veth-r3,10.1.2.2/24 dummy0,192.168.3.1/24; exec bash"

echo
echo "Para limpar o ambiente depois, execute: sudo bash cleanup_network.sh"

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
