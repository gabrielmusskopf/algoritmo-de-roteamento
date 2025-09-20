#!/bin/bash

# O objetivo deste script é criar um laboratório de rede virtual em uma única máquina Linux para 
# testar um protocolo de roteamento customizado (implementado em router.py).
#
# O ambiente simula uma topologia de rede com dois roteadores conectados via switch (bridge),
# permitindo a verificação da capacidade do protocolo de propagar rotas através de múltiplos 
# saltos (hops). 
#
# São utilizados namespaces distintos para simular um cenário mais próximo da realidade,
# onde cada roteador está isolado dos demais.
#
#  Topologia:
#  +------------------------------------------------------+
#  | Host (Root Namespace)                                |
#  |          +-----------------+                         |
#  |          |  Bridge 'br0'   | (Switch Virtual)        |
#  |          +-----------------+                         |
#  |                  |                                   |
#  |        +---------+---------+                         |
#  |        | (veth-br1)      | (veth-br2)                |
#  +--------|-----------------|----------------------------+
#           |                 |
#           | (veth-r1)       | (veth-r2)
#  +--------|-----------------|----------------------------+
#  |        |                 |                           |
#  | +-----------------+   +-----------------+            |
#  | | Namespace 'ns1' |   | Namespace 'ns2' |            |
#  | | IP: 10.90.80.1  |   | IP: 10.90.80.2  |            |
#  | | (Roteador 1)    |   | (Roteador 2)    |            |
#  | +-----------------+   +-----------------+            |
#  +------------------------------------------------------+
#
# Desenvolvido e testado em um Ubuntu 22.04

# --- Criação dos Namespaces ---
echo "=== Criando Network Namespaces 'ns1' e 'ns2'... ==="
sudo ip netns add ns1
sudo ip netns add ns2
echo "Namespaces criados."
echo

# --- Criação da Bridge no Host Principal ---
# Vai agir como um switch L2. Usando dessa forma, é possível vincular mais roteadores na mesma rede
echo "=== Configurando a Bridge 'br0' no host... ==="
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up
echo "Bridge criada e ativada."
echo

# --- Configuração do Roteador 1 (ns1) ---
echo "=== Configurando o ambiente para o Roteador 1... ==="
# Cria o "cabo" veth-r1 <=> veth-br1
sudo ip link add veth-r1 type veth peer name veth-br1
# Conecta uma ponta do cabo na bridge
sudo ip link set veth-br1 master br0
sudo ip link set veth-br1 up
# Move a outra ponta do cabo para dentro do namespace 'ns1'
sudo ip link set veth-r1 netns ns1
# Executa comandos DENTRO do namespace 'ns1'
sudo ip netns exec ns1 ip link set dev lo up
sudo ip netns exec ns1 ip link set dev veth-r1 up
sudo ip netns exec ns1 ip addr add 10.90.80.1/24 dev veth-r1
echo "Roteador 1 configurado em 'ns1' com IP 10.90.80.1"
echo

# --- Configuração do Roteador 2 (ns2) ---
echo "=== Configurando o ambiente para o Roteador 2... ==="
sudo ip link add veth-r2 type veth peer name veth-br2
sudo ip link set veth-br2 master br0
sudo ip link set veth-br2 up
sudo ip link set veth-r2 netns ns2
sudo ip netns exec ns2 ip link set dev lo up
sudo ip netns exec ns2 ip link set dev veth-r2 up
sudo ip netns exec ns2 ip addr add 10.90.80.2/24 dev veth-r2
echo "Roteador 2 configurado em 'ns2' com IP 10.90.80.2"
echo

# Para testar o recebimento de rotas, foi adicionado uma rede ao r2 para que seja propagado para o r1
echo "--> Adicionando rede dummy 172.16.0.0/24 ao Roteador 2..."
sudo ip netns exec ns2 ip link add dummy0 type dummy
sudo ip netns exec ns2 ip link set dev dummy0 up
sudo ip netns exec ns2 ip addr add 172.16.0.1/24 dev dummy0

# --- Execução dos Processos ---
echo "=== Executando os roteadores em seus namespaces ==="
echo "--> Para iniciar os roteadores, execute o código no respectivo namespace. Exemplo:"
echo "    sudo ip netns exec ns1 python3 router.py 10.90.80.1 --interfaces veth-r1,10.90.80.1/24"
echo "    sudo ip netns exec ns2 python3 router.py 10.90.80.2 --interfaces veth-r2,10.90.80.2/24 dummy0,172.16.0.1/24"

echo
echo "Para limpar o ambiente depois, execute: sudo bash cleanup_network.sh"

# --- Cria o script de limpeza ---
cat << EOF > cleanup_network.sh
#!/bin/bash
echo "Limpando network namespaces e a bridge..."
sudo ip netns del ns1
sudo ip netns del ns2
sudo ip link del br0
echo "Ambiente limpo."
rm cleanup_network.sh
EOF
chmod +x cleanup_network.sh
