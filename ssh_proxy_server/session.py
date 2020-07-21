import logging
from socket import socket
import threading

from paramiko import Transport, AUTH_SUCCESSFUL
from paramiko.agent import AgentServerProxy

from ssh_proxy_server.interfaces.server import ProxySFTPServer
from ssh_proxy_server.interfaces.sftp import SFTPProxyServerInterface

from typing import (
    TYPE_CHECKING,
    Any,
    Optional,
    Text,
    Tuple,
    Type,
    Union
)
if TYPE_CHECKING:
    from ssh_proxy_server.server import SSHProxyServer
    from ssh_proxy_server.authentication import Authenticator
    from ssh_proxy_server.clients.ssh import SSHClient
    from ssh_proxy_server.clients.sftp import SFTPClient


class Session:
    CIPHERS = None

    def __init__(
        self,
        proxyserver: SSHProxyServer,
        client_socket: socket.socket,
        client_address: Tuple[Text, int],
        authenticator: Type[Authenticator],
        remoteaddr: Tuple[Text, int]
    ) -> None:

        self._transport: Optional[Transport] = None

        self.channel: Any = None

        self.proxyserver: SSHProxyServer = proxyserver
        self.client_socket: socket.socket = client_socket
        self.client_address: Tuple(Text, int) = client_address

        self.ssh: bool = False
        self.ssh_channel: Any = None
        self.ssh_client: SSHClient = None

        self.scp: bool = False
        self.scp_channel: Any = None
        self.scp_command: Union[bytes, Text] = ''

        self.sftp: bool = False
        self.sftp_channel: Any = None
        self.sftp_client: SFTPClient = None
        self.sftp_client_ready: threading.Event = threading.Event()

        self.username: Union[bytes, Text] = ''
        self.socket_remote_address: Tuple[Text, int] = remoteaddr
        self.remote_address: Tuple[Optional[Text], Optional[int]] = (None, None)
        self.key = None
        self.agent: AgentServerProxy = None
        self.authenticator: Authenticator = authenticator(self)

    @property
    def running(self) -> bool:
        return self.proxyserver.running

    @property
    def transport(self) -> Transport:
        if not self._transport:
            self._transport = Transport(self.client_socket)
            if self.CIPHERS:
                if not isinstance(self.CIPHERS, tuple):
                    raise ValueError('ciphers must be a tuple')
                self._transport.get_security_options().ciphers = self.CIPHERS
            self._transport.add_server_key(self.proxyserver.host_key)
            self._transport.set_subsystem_handler('sftp', ProxySFTPServer, SFTPProxyServerInterface)

        return self._transport

    def _start_channels(self) -> bool:
        # create client or master channel
        if self.ssh_client:
            self.sftp_client_ready.set()
            return True

        if not self.agent and self.authenticator.AGENT_FORWARDING:
            try:
                self.agent = AgentServerProxy(self.transport)
                self.agent.connect()
            except Exception:
                self.close()
                return False
        # Connect method start
        if not self.agent:
            self.channel.send('Kein SSH Agent weitergeleitet\r\n')
            return False

        if self.authenticator.authenticate() != AUTH_SUCCESSFUL:
            self.channel.send('Permission denied (publickey).\r\n')
            return False
        logging.info('connection established')

        # Connect method end
        if not self.scp and not self.ssh and not self.sftp:
            if self.transport.is_active():
                self.transport.close()
                return False

        self.sftp_client_ready.set()
        return True

    def start(self) -> bool:
        event = threading.Event()
        self.transport.start_server(
            event=event,
            server=self.proxyserver.authentication_interface(self)
        )

        while not self.channel:
            self.channel = self.transport.accept(0.5)
            if not self.running:
                if self.transport.is_active():
                    self.transport.close()
                return False

        if not self.channel:
            logging.error('error opening channel!')
            if self.transport.is_active():
                self.transport.close()
            return False

        # wait for authentication
        event.wait()

        if not self.transport.is_active():
            return False

        if not self._start_channels():
            return False

        logging.info("session started")
        return True

    def close(self) -> None:
        if self.transport.is_active():
            self.transport.close()
        if self.agent:
            self.agent.close()

    def __enter__(self) -> 'Session':
        return self

    def __exit__(self, value_type, value, traceback):
        self.close()
