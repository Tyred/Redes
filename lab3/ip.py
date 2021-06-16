from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.datagram_id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama

            ttl -= 1
            if ttl == 0:

                next_hop = self._next_hop(src_addr)

                header = struct.pack('!BBHHHBBH', (4 << 4) + 5, 0, 20 + 32 + len(payload), identification, 0, 64, IPPROTO_ICMP, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                header_icmp = struct.pack('!BBHI', 11, 0, 0, 0)

                checksum_icmp = calc_checksum(header_icmp + datagrama[:28])
                header_icmp = struct.pack('!BBHI', 11, 0, 0, checksum_icmp)

                checksum_ip = calc_checksum(header)
                header = struct.pack('!BBHHHBBH', (4 << 4) + 5, 0, 20 + 32 + len(payload), identification, 0, 64, IPPROTO_ICMP, checksum_ip) + str2addr(self.meu_endereco) + str2addr(src_addr)

                datagrama = header + header_icmp + datagrama[:28]

            else:
                header = struct.pack('!BBHHHBBH', (4 << 4) + 5, 0, 20 + len(payload), identification, 0, ttl, proto, 0) + str2addr(src_addr) + str2addr(dst_addr)
                checksum = calc_checksum(header)
                header = struct.pack('!BBHHHBBH', (4 << 4) + 5, 0, 20 + len(payload), identification, 0, ttl, proto, checksum) + str2addr(src_addr) + str2addr(dst_addr)
                datagrama = header + payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        val, = struct.unpack('!I', str2addr(dest_addr))

        biggest_prefix = -1
        chosen_next_hop = None
        for cidr, next_hop in self.tabela:
            cidr_split = cidr.split('/')
            cidr = cidr_split[0]
            bits = int(cidr_split[1])
            net, = struct.unpack('!I', str2addr(cidr))

            if (val >> 32-bits << 32-bits) == (net >> 32-bits << 32-bits):
                if (bits > biggest_prefix):
                    biggest_prefix = bits
                    chosen_next_hop = next_hop

        return chosen_next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        vihl = (4 << 4) + 5
        total_length = 20 + len(segmento)
        ttl = 64
        protocol = 6

        header = struct.pack('!BBHHHBBH', vihl, 0, total_length, self.datagram_id, 0, ttl, protocol, 0) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        checksum = calc_checksum(header)
        header = struct.pack('!BBHHHBBH', vihl, 0, total_length, self.datagram_id, 0, ttl, protocol, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr)

        datagrama = header + segmento

        self.enlace.enviar(datagrama, next_hop)
        self.datagram_id += 1