import logging
import os
import select
import socket
import time
import threading

from paramiko import RSAKey

from ssh_proxy_server.session import Session

from typing import (
    TYPE_CHECKING,
    List,
    Optional,
    Text,
    Tuple,
    Type
)
if TYPE_CHECKING:
    from ssh_proxy_server.forwarders.ssh import SSHBaseForwarder
    from ssh_proxy_server.forwarders.scp import SCPBaseForwarder
    from ssh_proxy_server.forwarders.sftp import SFTPHandlerBasePlugin
    from ssh_proxy_server.interfaces import BaseServerInterface
    from ssh_proxy_server.authentication import Authenticator


class SSHProxyServer:
    HOST_KEY_LENGTH: int = 2048
    SELECT_TIMEOUT: float = 0.5

    def __init__(
        self,
        listen_address: Tuple[Text, int],
        key_file: Optional[Text] = None,
        ssh_interface: Optional[Type[SSHBaseForwarder]] = None,
        scp_interface: Optional[Type[SCPBaseForwarder]] = None,
        sftp_handler: Optional[Type[SFTPHandlerBasePlugin]] = None,
        authentication_interface: Optional[Type[BaseServerInterface]] = None,
        authenticator: Optional[Type[Authenticator]] = None,
        transparent: bool = False
    ) -> None:
        self._threads: List[threading.Thread] = []
        self._hostkey: Optional[RSAKey] = None

        self.listen_address: Tuple[Text, int] = listen_address
        self.running: bool = False

        self.key_file: Optional[Text] = key_file

        self.ssh_interface: Optional[Type[SSHBaseForwarder]] = ssh_interface
        self.scp_interface: Optional[Type[SCPBaseForwarder]] = scp_interface
        self.sftp_handler: Optional[Type[SFTPHandlerBasePlugin]] = sftp_handler
        self.authentication_interface: Optional[Type[BaseServerInterface]] = authentication_interface
        self.authenticator: Optional[Type[Authenticator]] = authenticator
        self.transparent: bool = transparent

    @property
    def host_key(self) -> Optional[RSAKey]:
        if not self._hostkey:
            if not self.key_file:
                self._hostkey = RSAKey.generate(bits=self.HOST_KEY_LENGTH)
                logging.warning("created temporary private key!")
            else:
                if not os.path.isfile(self.key_file):
                    raise FileNotFoundError("host key '{}' file does not exist".format(self.key_file))
                try:
                    self._hostkey = RSAKey(filename=self.key_file)
                except Exception:
                    logging.error('only rsa key files are supported!')
        return self._hostkey

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.transparent:
            sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        sock.bind(self.listen_address)
        sock.listen(5)

        logging.info('listen on %s', self.listen_address)
        self.running = True
        try:
            while self.running:
                readable = select.select([sock], [], [], self.SELECT_TIMEOUT)[0]
                if len(readable) == 1 and readable[0] is sock:
                    client, addr = sock.accept()
                    remoteaddr = client.getsockname()
                    logging.info('incoming connection from %s to %s', str(addr), remoteaddr)

                    thread = threading.Thread(target=self.create_session, args=(client, addr, remoteaddr))
                    thread.start()
                    self._threads.append(thread)
        except KeyboardInterrupt:
            self.running = False
        finally:
            sock.close()
            for thread in self._threads[:]:
                thread.join()

    def create_session(self, client: socket.socket, addr: Tuple[Text, int], remoteaddr: Tuple[Text, int]) -> None:
        try:
            with Session(self, client, addr, self.authenticator, remoteaddr) as session:
                if session.start():
                    time.sleep(0.1)
                    if session.ssh and self.ssh_interface:
                        session.ssh = False
                        self.ssh_interface(session).forward()
                    elif session.scp and self.scp_interface:
                        session.scp = False
                        self.scp_interface(session).forward()
                    while True:
                        time.sleep(1)
                else:
                    logging.warning("Session not started")
                    self._threads.remove(threading.current_thread())
        except Exception:
            logging.exception("error handling session")
        logging.info("session closed")
