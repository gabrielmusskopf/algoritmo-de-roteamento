# Algoritmo de roteamento

Um algoritmo de roteamento de pacotes IP para ser executado em sistemas Unix representando roteadores. Um algoritmo de roteamento é um software que interage com a tabela de roteamento do sistema operacional, geralmente executado como um daemon, adicionando e removendo rotas conhecidas. Isso é feito através da descoberta de redes com a troca de mensagens entre os roteadores conhecidos, informando sobre suas rotas/topologia.

# Quickstart

Para executar esse algoritmo você precisa ter Python instalado (testado com Python ≥ 3.10.0) e as interfaces de rede que devem estar diretamente conectadas ao roteador.

```bash
python router.py <id do roteador> --interfaces <nome>,<ip><CIDR> <nome>,<ip><CIDR>
```

Existem scripts prontos, `2_routers_switch.sh`, `3_routers.sh` e `4_routers.sh`, que criam exemplos de topologia usando namespaces do Unix. Esses são um bom caminho para testar o algoritmo.

# Sobre o protocolo

```
+-------------+-----------+-------+
| Versão (1B) | Tipo (1B) | Dados |
+-------------+-----------+-------+
```

As mensagens são trocadas usando o protocolo UDP, visto que é um algoritmo para ser usado em redes internas, portanto, mais confiáveis. A versão é utilizada para que o roteador saiba se ele consegue interpretar a mensagem que da versão específica que recebeu. Os tipos de mensagem estão descritos a baixo, cada um contém um dado particular. Tipos:

**PACKET_TYPE_UPDATE (1)**

Pacote com os dados das rotas que não foram recebidas por essa interface. Dados são
ip,custo,latência,perda separados por ;. Exemplo 192.168.1.0,2,15,2;10.10.1.0,3,12,3. Os bytes
de dados trafegam convertidos com utf-8.
Esse pacote instrui o roteador a atualizar sua tabela de roteamento, se necessário.
Caso a rota recebida não exista na tabela, ela é adicionada na tabela interna e na tabela do OS.
Caso a rota foi recebida pelo mesmo vizinho, atualiza a tabela interna independente das
métricas. Nesse caso não é preciso atualizar a tabela do OS.
Caso a rota recebida não veio pelo mesmo vizinho, a rota atualiza se, seguindo a ordem:
1. O número de saltos seja menor
2. A perda de pacotes seja menor
3. A latência seja menor

Se alguma dessas condições for atendida, respeitando essa ordem, a tabela interna é atualizada,
a rota antiga é removida da tabela do OS e a nova rota é adicionada.
Não espera nenhuma resposta.

**PACKET_TYPE_LATENCY_REQUEST (2)**

Pacotes para medição das métricas. Dados são um token aleatório de 1 byte para identificar a
requisição. A medição de latência é feita enviando para todos os vizinhos diretamente
conectados um pacote com um token único. Esse token é armazenado em um mapa com o momento em
que foi enviado. Espera uma resposta PACKET_TYPE_LATENCY_REPLY.

**PACKET_TYPE_LATENCY_REPLY (3)**

Resposta ao pacote de PACKET_TYPE_LATENCY_REQUEST. Dados são o token recebido na requisição.
Ao receber esse pacote, o roteador usa o tempo que a requisição foi enviada
(presente no mapa) e o tempo atual para calcular o RTT (Round Trip Time). Tendo o RTT, o valor
é armazenado/atualizado no mapa de latência para os vizinhos.

**PACKET_TYPE_LOSS_REQUEST (4)**

Pacotes para medição da perda. A medição de perda é feita enviando para todos os vizinhos
diretamente conectados múltiplos pacotes desse tipo e contando quantos foram recebidos. Os
dados incluem um número de sessão do teste, usado para controlar de qual teste a resposta se
refere, e um número de sequência, usado para controlar quantos pacotes foram perdidos. Espera
uma resposta PACKET_TYPE_LOSS_REPLY para cada pacote enviado.
O roteador que iniciou o teste mantém um mapa do número de sessão para um objeto de controle
do teste, contendo por exemplo, o número de pacotes enviados e recebidos. Esse objeto de
controle é usado para calcular a perda para o vizinho.

**PACKET_TYPE_LOSS_REPLY (5)**

Resposta ao pacote de PACKET_TYPE_LOSS_REQUEST. Os dados são um eco do que foi recebido na
requisição: o número da sessão e o número de sequência.
Ao receber esse pacote, o número de pacotes recebidos para a sessão é incrementado.
