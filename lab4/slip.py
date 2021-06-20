import struct

class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.residual_data = b''

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        datagrama_len = len(datagrama)
        datagrama = struct.unpack(str(datagrama_len) + 'c', datagrama)
        new_datagrama = b''
        for byte in datagrama:
            if byte == b'\xc0':
                new_datagrama += b'\xdb\xdc'
            elif byte == b'\xdb':
                new_datagrama += b'\xdb\xdd'
            else:
                new_datagrama += byte
        self.linha_serial.enviar(b'\xc0' + new_datagrama + b'\xc0')

    def __raw_recv(self, dados):
        self.residual_data += dados
        if self.residual_data.find(b'\xc0') != -1:
            datagrama = self.residual_data.split(b'\xc0')
            for i in range(len(datagrama)-1):
                if datagrama[i] != b'':
                    datagrama_len = len(datagrama[i])
                    datagrama[i] = struct.unpack(str(datagrama_len) + 'c', datagrama[i])
                    new_datagrama = b''
                    is_db = False
                    for byte in datagrama[i]:
                        if is_db:
                            if byte == b'\xdc':
                                new_datagrama += b'\xc0'
                            elif byte == b'\xdd':
                                new_datagrama += b'\xdb'
                            else:
                                new_datagrama += byte        
                        
                        elif byte != b'\xdb':
                            new_datagrama += byte
                        is_db = byte == b'\xdb'
                    try:
                        self.callback(new_datagrama)
                    except:
                        pass
               
            self.residual_data = datagrama[-1]
