import asyncio
import os
import struct
import sys
from tcputils import *


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão

            # Certificando que o seq do segundo aperto nao e 0.
            seq_noHandShake = 0
            while seq_noHandShake == 0: # ARRUMAR ISSO AQUI DEPOIS ...
                seq_noHandShake = struct.unpack('I', os.urandom(4))[0] % 60500

            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no+1, ack_no, seq_noHandShake+1, src_addr, src_port, dst_addr, dst_port) 
            
            # Segundo aperto da mao.
            segmentDest = fix_checksum(make_header(dst_port , src_port, seq_noHandShake, (seq_no+1), FLAGS_SYN | FLAGS_ACK), dst_addr, src_addr)
            
            self.rede.enviar(segmentDest, src_addr)
            # Envia um pacote com SYN, ACK (ackNum = seqNum+1)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, expectedSeqNum, ackNum,seq_noHandShake, srcAddr, srcPort, dstAddr, dstPort):
        self.servidor = servidor
        self.id_conexao = id_conexao
        # Adicionado: seq e ack e enderecos e portas.
        self.expectedSeqNum = expectedSeqNum # Usado no passo 2
        self.ackNum = ackNum # Usado no passo 3
        self.seq_noHandShake = seq_noHandShake # Usado no passo 3
        self.srcAddr = srcAddr
        self.srcPort = srcPort
        self.dstAddr = dstAddr
        self.dstPort = dstPort
        # ---------------------
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.

        # Apenas necessario garantir de ACK o pacote correto enviado.
        if seq_no == self.expectedSeqNum:
            segmentDest = fix_checksum(make_header(self.dstPort , self.srcPort, seq_no, (seq_no+len(payload)), FLAGS_ACK), self.dstAddr, self.srcAddr) # Montando pacote de ACK
            self.seq_no = seq_no
            self.servidor.rede.enviar(segmentDest, self.srcAddr) # Enviando o pacote ACK montado
            self.expectedSeqNum = self.expectedSeqNum + len(payload) # Atulizando o proximo seq esperado.
            self.callback(self, payload) # Mandando para a camada de aplicação. (TIPO: HTTTP ou o NC)

        print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados): # Passo 3.
        """
        Usado pela camada de aplicação para enviar dados
        """
        # TODO: implemente aqui o envio de dados.
        # Chame self.servidor.rede.enviar(segmento, dest_addr) para enviar o segmento
        # que você construir para a camada de rede.
        # Lembrar de dividir o payload em MSG...
        ## --- Ta enviando mas esta enviando errado ---
        ## Como enfiar o payload nessa bagaça
        #print(self.ackNum)
        #print(self.expectedSeqNum)
        #print(self.seq_no)

        # ------------------------------------------------------------------------------------
        # TODO: EXPECTEDSeqNum se mantem igual, o que vai incrementar é o seq_noHandShake.
        # - Incrementar eles com o tamanho do payload do segmento.
        # - Descobrir como inserir um payload no segmento.
        # - Dividir os pacotes que serao inviados em MSG.
        # - Lembrar de incrementar a variavel na medidade do tamanho dos pacotes.

        # Dividindo dados em partes com tamanho MSS.
        ## lista de partes MSS de dados.
        partes = [dados[i:i+MSS] for i in range(0, len(dados), MSS)]

        ## POR ALGUM MOTIVO NAO TA CHEGANDO O PAYLOAD ...
        for parte in partes:
            segmentDest = fix_checksum(make_header(self.srcPort , self.dstPort, self.seq_noHandShake, self.expectedSeqNum, FLAGS_ACK) + parte, self.srcAddr, self.dstAddr) 
            self.servidor.rede.enviar(segmentDest, self.dstAddr) 
            self.expectedSeqNum = self.expectedSeqNum + len(parte)
            #self.callback(self, parte)

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # TODO: implemente aqui o fechamento de conexão
        pass
