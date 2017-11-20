################################################################################
#
#   Copyright 2017 Rockwell Collins Inc,.
#
################################################################################
#
#  This file is part of fuddly.
#
#  fuddly is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  fuddly is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with fuddly. If not, see <http://www.gnu.org/licenses/>
#
################################################################################

import collections
import copy
import datetime
import fcntl
import select
import socket
import struct
import sys
import threading
import time
import uuid
from _socket import error as socket_error
from scapy.sendrecv import sendp

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
     
    

from framework.data import Data
from framework.node import Node, NodeSemanticsCriteria
from framework.target_helpers import Target, TargetFeedback, TargetStuck

class Layer2NetworkTarget(Target):
    '''Generic target class for interacting with a network resource at layer 2.
    Can be used directly, but some methods may require to be overloaded to
    fit your needs.
    '''

    UNKNOWN_SEMANTIC = "Unknown Semantic"
    CHUNK_SZ = 2048
    _INTERNALS_ID = 'L2NetworkTarget()'
    

    UDP_TYPE = "UDP"

    _feedback_mode = Target.FBK_WAIT_FULL_TIME
    supported_feedback_mode = [Target.FBK_WAIT_FULL_TIME, Target.FBK_WAIT_UNTIL_RECV]

    def __init__(self, 
                 targetIP,
                 sourceIP,
                 port_src = 12345, 
                 port_dst = 12345,
                 mac_src = None,
                 mac_dst = None,
                 transport_type = UDP_TYPE,
                 interface = 'eth0',
                 data_semantics=UNKNOWN_SEMANTIC ):
        """
        TODO UPDATE THE PORT LIST
        Args:
          targetIP (str): IP address of destination field in the IP header.
          sourceIP (str): IP address of the source field in the IP header.
          port_src  (int): Source port for the protocol layer.
          port_dst (int): Destination port for the protocol layer.
          mac_src (str): Source MAC address to put into the ethernet frame.
          mac_dst (str): Destination MAC address to put into the ethernet frame.
          transport_type (str): A string that determines what type of transportation protocol is
            utilized.  Possible list options are "UDP" and "TCP".
          interface (str): The network interface to send the traffic through.
        """

        Target.__init__(self)

        if not self._is_valid_transport_type(transport_type):
            raise ValueError("Unrecognized transportation layer type")
        
        self._target_info = {}
        self._target_info['TargetIP'] = targetIP
        self._target_info['SourceIP'] = sourceIP
        self._target_info['TargetPort'] = port_dst
        self._target_info['SourcePort'] = port_src
        self._target_info['TargetMAC' ] = mac_dst
        self._target_info['SourceMAC' ] = mac_src
        self._target_info['Transport' ] = transport_type
        self._target_info['Interface' ] = interface
        
        self.targetInfo = {}
        self.targetInfo[data_semantics] = self._target_info

        self.known_semantics = {data_semantics}


        self._feedback = TargetFeedback()

        self._fbk_handling_lock = threading.Lock()
        self.socket_desc_lock = threading.Lock()

        self.set_timeout(fbk_timeout=6, sending_delay=4)

        self.feedback_length = None  # if specified, timeout will be ignored

        self.stop_event = threading.Event()
    # end __init__


    def _is_valid_transport_type(self, transport_type):
        '''
        TODO NEED TO ADD TCP INTO THIS LIST
        '''
        retVal = False
        if transport_type == self.UDP_TYPE:
                retVal = True
        return retVal
    # end _is_valid_transport_type


    def set_timeout(self, fbk_timeout, sending_delay):
        '''
        Set the time duration for feedback gathering and the sending delay above which
        we give up:
        - sending data to the target (client mode)
        - waiting for client connections before sending data to them (server mode)

        Args:
            fbk_timeout: time duration for feedback gathering (in seconds)
            sending_delay: sending delay (in seconds)
        '''
        self.set_sending_delay(sending_delay)
        self.set_feedback_timeout(fbk_timeout)

    def _set_feedback_timeout_specific(self, fbk_timeout):
        self._feedback_timeout = fbk_timeout

    def initialize(self):
        '''
        To be overloaded if some intial setup for the target is necessary.
        '''
        return True

    def terminate(self):
        '''
        To be overloaded if some cleanup is necessary for stopping the target. 
        '''
        return True


    def _custom_data_handling_before_emission(self, data_list):
        '''To be overloaded if you want to perform some operation before
        sending `data_list` to the target.

        Args:
          data_list (list): list of Data objects that will be sent to the target.
        '''
        pass

    def _feedback_handling(self, fbk, ref):
        '''To be overloaded if feedback from the target need to be filtered
        before being logged and/or collected in some way and/or for
        any other reasons.

        Args:
          fbk (bytes): feedback received by the target through a socket referenced by `ref`.
          ref (string): user-defined reference of the socket used to retrieve the feedback.

        Returns:
          tuple: a tuple `(new_fbk, status)` where `new_fbk` is the feedback
            you want to log and `status` is a status that enables you to notify a problem to the
            framework (should be positive if everything is fine, otherwise should be negative).
        '''
        return fbk, 0

    def cleanup(self):

        self.feedback_thread_qty = 0
        self.feedback_complete_cpt = 0

        return True

    def listen_to(self, host, port, ref_id,
                  socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                  chk_size=CHUNK_SZ, wait_time=None, hold_connection=True):
        '''
        TODO THIS NEEDS TO BE CUSTOM FOR THE FEED BACK OF THE LAYER 2 SOCKET
        Used for collecting feedback from the target while it is already started.
        '''
        pass


    def _raw_listen_to(self, host, port, ref_id,
                       socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                       chk_size=CHUNK_SZ, wait_time=None):
        pass
#
#        if wait_time is None:
#            wait_time = self._feedback_timeout
#
#        initial_call = False
#        if (host, port) not in self._server_sock2hp.values():
#            initial_call = True
#
#        connected_client_event = threading.Event()
#        self._listen_to_target(host, port, socket_type,
#                               self._handle_connection_to_fbk_server, args=(ref_id, chk_size, connected_client_event))
#
#        if initial_call or not self.hold_connection[(host, port)]:
#            connected_client_event.wait(wait_time)
#            if not connected_client_event.is_set():
#                self._logger.log_comment('WARNING: Feedback from ({:s}:{:d}) is not available as no client connects to us'.format(host, port))


    def connect_to(self, host, port, ref_id,
                   socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                   chk_size=CHUNK_SZ, hold_connection=True):
        '''
        Used for collecting feedback from the target while it is already started.
        '''
        self.hold_connection[(host, port)] = hold_connection
        s = self._raw_connect_to(host, port, ref_id, socket_type, chk_size, hold_connection=hold_connection)
        self._dynamic_interfaces[(host, port)] = (s, ref_id)

        return s

    def _raw_connect_to(self, host, port, ref_id,
                        socket_type=(socket.AF_INET, socket.SOCK_STREAM),
                        chk_size=CHUNK_SZ, hold_connection=True):
        s = self._connect_to_target(host, port, socket_type)
        if s is None:
            self._logger.log_comment('WARNING: Unable to connect to {:s}:{:d}'.format(host, port))
            return None
        else:
            with self.socket_desc_lock:
                if s not in self._additional_fbk_sockets:
                    self._additional_fbk_sockets.append(s)
                    self._additional_fbk_ids[s] = ref_id
                    self._additional_fbk_lengths[s] = chk_size

        return s


    def start(self):
        self.stop_event.clear()

#         # Used by _raw_listen_to()
#         self._server_sock2hp = {}
#         self._server_thread_share = {}
#         self._last_client_sock2hp = {}  # only for hold_connection
#         self._last_client_hp2sock = {}  # only for hold_connection
#         self._raw_server_private = {}  # useful only for hold_connection
#
#         # Used by _raw_connect_to()
#         self._hclient_sock2hp = {}  # only for hold_connection
#         self._hclient_hp2sock = {}  # only for hold_connection
#
#         self._additional_fbk_sockets = []
#         self._additional_fbk_ids = {}
#         self._additional_fbk_lengths = {}
#         self._dynamic_interfaces = {}
        self._feedback_handled = None
        self.feedback_thread_qty = 0
        self.feedback_complete_cpt = 0
        self._sending_id = 0
        self._initial_sending_id = -1
        self._first_send_data_call = True
        self._thread_cpt = 0
        self._last_ack_date = None  # Note that `self._last_ack_date`
                                    # could be updated many times if
                                    # self.send_multiple_data() is
                                    # used.
#         self._connect_to_additional_feedback_sockets()
# 
#         for k, mac_src in self._mac_src.items():
#             if mac_src is not None:
#                 if mac_src:
#                     self.record_info('*** Detected HW address for {!s}: {!s} ***'
#                                      .format(k[0], mac_src))
#                 else:
#                     self.record_info('*** WARNING: HW Address not detected for {!s}! ***'
#                                      .format(k[0]))

        return self.initialize()

    def stop(self):
        self.stop_event.set()

        return self.terminate()

    def send_data(self, data, from_fmk=False):
        assert data is not None
        self._before_sending_data(data, from_fmk)
        target = self._get_net_info_from(data)

        s = self._get_scapy_data(target, data)

        if s is None:
            err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(target["TargetIP"], target["TargetPort"])
            self._feedback.add_fbk_from(self._INTERNALS_ID, err_msg, status=-1)
        else:
            self._send_data([s], {s:(data,)}, self._sending_id, from_fmk, iface=target['Interface'])


    def send_multiple_data(self, data_list, from_fmk=False):
        self._before_sending_data(data_list, from_fmk)
        sockets = []
        data_refs = {}
        connected_client_event = {}
        client_event = None

        sending_list = []
        if data_list is None:
            # If data_list is None, it means that we want to collect feedback from every interface
            # without sending data.
            pass
            # TODO there really isn't anything we can do at a layer two interface with multiple interfaces
#             for key in self.known_semantics:
#                 host = self._host[key]
#                 port = self._port[key]
#                 socket_type = self._socket_type[key]
#                 server_mode = self.server_mode[(host, port)]
#                 if self.hold_connection[(host, port)]:
#                     # Collecting feedback makes sense only if we keep the socket (thus, 'hold_connection'
#                     # has to be True) or if a data callback wait for feedback.
#                     sending_list.append((None, host, port, socket_type, server_mode))
        else:
            for data in data_list:
                host, port, socket_type, server_mode = self._get_net_info_from(data)
                d = data.to_bytes()
                sending_list.append((d, host, port, socket_type, server_mode))

        for data, host, port, socket_type, server_mode in sending_list:
            if server_mode:
                connected_client_event[(host, port)] = threading.Event()
                self._listen_to_target(host, port, socket_type,
                                       self._handle_target_connection,
                                       args=(data, host, port,
                                             connected_client_event[(host, port)], from_fmk))
            else:
                s = self._connect_to_target(host, port, socket_type)
                if s is None:
                    err_msg = '>>> WARNING: unable to send data to {:s}:{:d} <<<'.format(host, port)
                    self._feedback.add_fbk_from(self._INTERNALS_ID, err_msg, status=-2)
                else:
                    if s not in sockets:
                        sockets.append(s)
                        data_refs[s] = (data, host, port, None)

        if data_refs:
            self._send_data(sockets, data_refs, self._sending_id, from_fmk)
        else:
            # this case exist when data are only sent through 'server_mode'-configured interfaces
            # or a connection error has occurred.
            pass

        if data_list is None:
            return

        if connected_client_event:
            t0 = datetime.datetime.now()
            duration = 0
            client_event = connected_client_event
            client_event_copy = copy.copy(connected_client_event)
            while duration < self.sending_delay:
                if len(client_event) != len(client_event_copy):
                    client_event = copy.copy(client_event_copy)
                for ref, event in client_event.items():
                    event.wait(0.2)
                    if event.is_set():
                        del client_event_copy[ref]
                now = datetime.datetime.now()
                duration = (now - t0).total_seconds()

            for ref, event in connected_client_event.items():
                host, port = ref
                if not event.is_set():
                    err_msg = ">>> WARNING: unable to send data because the target did not connect" \
                              " to us [{:s}:{:d}] <<<".format(host, port)
                    self._feedback.add_fbk_from(self._INTERNALS_ID, err_msg, status=-1)

    def _get_data_semantic_key(self, data):
        if not isinstance(data.content, Node):
            if data.is_empty():
                print('\n*** ERROR: Empty data has been received!')
            return self.UNKNOWN_SEMANTIC

        semantics = data.content.get_semantics()
        if semantics is not None:
            matching_crit = semantics.what_match_from(self.known_semantics)
        else:
            matching_crit = None

        if matching_crit:
            key = matching_crit[0]
        else:
            key = self.UNKNOWN_SEMANTIC

        return key

    def _get_net_info_from(self, data):
        key = self._get_data_semantic_key(data)
        target = self.targetInfo[key]
        return target

    def _get_scapy_data(self, target, data):
        
        ethPkt = Ether( src = target["SourceMAC"], dst=target['TargetMAC'])
        ipPkt = IP(src=target['SourceIP'], dst=target['TargetIP'], flags='DF', ttl=1)
        # todo need to figure out how to pass TTL Down
        # TODO need to figure out how to pass the calc checksum down
        udpPkt = UDP(sport=target['SourcePort'], dport=target['TargetPort'])
        dataPkt = Raw(load=data.to_bytes() if isinstance(data, Data) else data)
        
        pkt = ethPkt / ipPkt / udpPkt / dataPkt
        return pkt
        
    def _connect_to_target(self, host, port, socket_type):
        if self.hold_connection[(host, port)] and (host, port) in self._hclient_hp2sock.keys():
            try:
                fd = self._hclient_hp2sock[(host, port)].fileno()
                if fd == -1:
                    # if the socket has been closed, -1 is received by python3
                    # (with python2 previous instruction raise a Bad file descriptor Exception)
                    raise OSError
            except Exception:
                print('\n*** WARNING: Current socket was closed unexpectedly! --> create new one.')
                # we remove the bad references then go on with the rest of the function
                with self.socket_desc_lock:
                    del self._hclient_sock2hp[self._hclient_hp2sock[(host, port)]]
                    del self._hclient_hp2sock[(host, port)]
            else:
                return self._hclient_hp2sock[(host, port)]

        skt_sz = len(socket_type)
        if skt_sz == 2:
            family, sock_type = socket_type
            proto = 0
        else:
            family, sock_type, proto = socket_type

        s = socket.socket(*socket_type)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        s.settimeout(self.sending_delay)

        if sock_type == socket.SOCK_RAW:
            assert port == socket.ntohs(proto)
            try:
                s.bind((host, port))
            except socket.error as serr:
                print('\n*** ERROR(while binding socket -- host={!s} port={:d}): {:s}'.format(host, port, str(serr)))
                return False
        else:
            try:
                s.connect((host, port))
            except socket_error as serr:
                # if serr.errno != errno.ECONNREFUSED:
                print('\n*** ERROR(while connecting): ' + str(serr))
                return None

            s.setblocking(0)

        if self.hold_connection[(host, port)]:
            self._hclient_sock2hp[s] = (host, port)
            self._hclient_hp2sock[(host, port)] = s

        return s


    def _listen_to_target(self, host, port, socket_type, func, args=None):

        def start_raw_server(serversocket, sending_event, notif_host_event):
            server_thread = threading.Thread(None, self._raw_server_main, name='SRV-' + '',
                                             args=(serversocket, host, port, sock_type, func,
                                                   sending_event, notif_host_event))
            server_thread.start()

        skt_sz = len(socket_type)
        if skt_sz == 2:
            family, sock_type = socket_type
            proto = 0
        else:
            family, sock_type, proto = socket_type

        if (host, port) in self._server_sock2hp.values():
            # After data has been sent to the target that first
            # connect to us, new data is sent through the same socket
            # if hold_connection is set for this interface. And new
            # connection will always receive the most recent data to
            # send.
            if sock_type == socket.SOCK_DGRAM or sock_type == socket.SOCK_RAW:
                with self._server_thread_lock:
                    self._server_thread_share[(host, port)] = args
                if self.hold_connection[(host, port)] and (host, port) in self._last_client_hp2sock:
                    sending_event, notif_host_event = self._raw_server_private[(host, port)]
                    sending_event.set()
                    # serversocket, _ = self._last_client_hp2sock[(host, port)]
                    # start_raw_server(serversocket)
                    notif_host_event.wait(5)
                    notif_host_event.clear()
            else:
                with self._server_thread_lock:
                    self._server_thread_share[(host, port)] = args
                    if self.hold_connection[(host, port)] and (host, port) in self._last_client_hp2sock:
                        csocket, addr = self._last_client_hp2sock[(host, port)]
                    else:
                        csocket = None
                if csocket:
                    func(csocket, addr, args)
            return True

        serversocket = socket.socket(*socket_type)
        if sock_type != socket.SOCK_RAW:
            serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            assert port == socket.ntohs(proto)

        try:
            serversocket.bind((host, port))
        except socket.error as serr:
            print('\n*** ERROR(while binding socket|host={!s},port={:d}): {:s}'.format(host, port, str(serr)))
            return False

        serversocket.settimeout(self.sending_delay)

        self._server_sock2hp[serversocket] = (host, port)
        with self._server_thread_lock:
            self._server_thread_share[(host, port)] = args

        if sock_type == socket.SOCK_STREAM:
            serversocket.listen(5)
            server_thread = threading.Thread(None, self._server_main, name='SRV-' + '',
                                             args=(serversocket, host, port, func))
            server_thread.start()

        elif sock_type == socket.SOCK_DGRAM or sock_type == socket.SOCK_RAW:
            sending_event = threading.Event()
            notif_host_event = threading.Event()
            self._raw_server_private[(host, port)] = (sending_event, notif_host_event)
            self._last_client_hp2sock[(host, port)] = (serversocket, None)
            self._last_client_sock2hp[serversocket] = (host, port)
            start_raw_server(serversocket, sending_event, notif_host_event)
            sending_event.set()
        else:
            raise ValueError("Unrecognized socket type")

    # For SOCK_STREAM
    def _server_main(self, serversocket, host, port, func):
        while not self.stop_event.is_set():
            try:
                # accept connections from outside
                (clientsocket, address) = serversocket.accept()
            except socket.timeout:
                pass
            except OSError as e:
                if e.errno == 9: # [Errno 9] Bad file descriptor
                    # TOFIX: It may occur with python3.
                    # In this case the resource seem to have been released by
                    # the OS whereas there is still a reference on it.
                    pass
                else:
                    raise
            else:
                with self._server_thread_lock:
                    args = self._server_thread_share[(host, port)]
                func(clientsocket, address, args)

    # For SOCK_RAW and SOCK_DGRAM
    def _raw_server_main(self, serversocket, host, port, sock_type, func,
                         sending_event, notif_host_event):
        while True:

            sending_event.wait()
            sending_event.clear()
            if self.stop_event.is_set():
                notif_host_event.set()
                break

            with self._server_thread_lock:
                args = self._server_thread_share[(host, port)]

            notif_host_event.set()

            target_address, wait_for_client = self._server_mode_additional_info[(host, port)]
            if func == self._handle_connection_to_fbk_server:
                # args = fbk_id, fbk_length, connected_client_event
                assert args[0] in self._additional_fbk_desc
                wait_before_sending = False
            elif func == self._handle_target_connection:
                # args = data, host, port, connected_client_event, from_fmk
                if args[0] is None:
                    # In the case 'data' is None there is no data to send,
                    # thus we are requested to only collect feedback
                    wait_before_sending = False
                elif target_address is not None:
                    wait_before_sending = wait_for_client
                elif sock_type == socket.SOCK_RAW:
                    # in this case target_address is not provided, but it is OK if it is a SOCK_RAW
                    wait_before_sending = wait_for_client
                else:
                    wait_before_sending = True
            else:
                raise ValueError

            retry = 0
            while retry < 10:
                try:
                    if wait_before_sending:
                        data, address = serversocket.recvfrom(self.CHUNK_SZ)
                    else:
                        data, address = None, None
                except socket.timeout:
                    break
                except OSError as e:
                    if e.errno == 9: # [Errno 9] Bad file descriptor
                        break
                    elif e.errno == 11: # [Errno 11] Resource temporarily unavailable
                        retry += 1
                        time.sleep(0.5)
                        continue
                    else:
                        raise
                except socket.error as serr:
                    if serr.errno == 11:  # [Errno 11] Resource temporarily unavailable
                        retry += 1
                        time.sleep(0.5)
                        continue
                else:
                    address = address if target_address is None else target_address
                    serversocket.settimeout(self.feedback_timeout)
                    func(serversocket, address, args, pre_fbk=data)
                    break

    def _handle_connection_to_fbk_server(self, clientsocket, address, args, pre_fbk=None):
        fbk_id, fbk_length, connected_client_event = args
        connected_client_event.set()
        with self.socket_desc_lock:
            self._additional_fbk_sockets.append(clientsocket)
            self._additional_fbk_ids[clientsocket] = fbk_id
            self._additional_fbk_lengths[clientsocket] = fbk_length

    def _handle_target_connection(self, clientsocket, address, args, pre_fbk=None):
        data, host, port, connected_client_event, from_fmk = args
        if self.hold_connection[(host, port)]:
            with self._server_thread_lock:
                self._last_client_hp2sock[(host, port)] = (clientsocket, address)
                self._last_client_sock2hp[clientsocket] = (host, port)
        connected_client_event.set()
        self._send_data([clientsocket], {clientsocket:(data, host, port, address)}, self._sending_id,
                        from_fmk=from_fmk, pre_fbk={clientsocket: pre_fbk})


    def _collect_feedback_from(self, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                               send_id, fbk_timeout, from_fmk, pre_fbk):

        def _check_and_handle_obsolete_socket(skt, error=None, error_list=None):
            # print('\n*** NOTE: Remove obsolete socket {!r}'.format(socket))
            try:
                epobj.unregister(skt)
            except ValueError as e:
                # in python3, file descriptor == -1 witnessed (!?)
                print('\n*** ERROR(check obsolete socket): ' + str(e))
            except socket.error as serr:
                # in python2, bad file descriptor (errno 9) witnessed
                print('\n*** ERROR(check obsolete socket): ' + str(serr))

            self._server_thread_lock.acquire()
            if skt in self._last_client_sock2hp.keys():
                if error is not None:
                    error_list.append((fbk_ids[skt], error))
                host, port = self._last_client_sock2hp[skt]
                del self._last_client_sock2hp[skt]
                del self._last_client_hp2sock[(host, port)]
                self._server_thread_lock.release()
            else:
                self._server_thread_lock.release()
                with self.socket_desc_lock:
                    if skt in self._hclient_sock2hp.keys():
                        if error is not None:
                            error_list.append((fbk_ids[skt], error))
                        host, port = self._hclient_sock2hp[skt]
                        del self._hclient_sock2hp[skt]
                        del self._hclient_hp2sock[(host, port)]
                    if skt in self._additional_fbk_sockets:
                        if error is not None:
                            error_list.append((self._additional_fbk_ids[skt], error))
                        self._additional_fbk_sockets.remove(skt)
                        del self._additional_fbk_ids[skt]
                        del self._additional_fbk_lengths[skt]

        chunks = collections.OrderedDict()
        t0 = datetime.datetime.now()
        duration = 0
        first_pass = True
        ack_date = None
        dont_stop = True

        bytes_recd = {}
        for fd in fbk_sockets:
            bytes_recd[fd] = 0
            chunks[fd] = []
            if pre_fbk is not None and fd in pre_fbk and pre_fbk[fd] is not None:
                chunks[fd].append(pre_fbk[fd])

        socket_errors = []
        has_read = False

        while dont_stop:
            ready_to_read = []
            for fd, ev in epobj.poll(timeout=0.05):
                skt = fileno2fd[fd]
                if ev != select.EPOLLIN:
                    _check_and_handle_obsolete_socket(skt, error=ev, error_list=socket_errors)
                    if skt in fbk_sockets:
                        fbk_sockets.remove(skt)
                    continue
                ready_to_read.append(skt)

            now = datetime.datetime.now()
            duration = (now - t0).total_seconds()
            if ready_to_read:
                if first_pass:
                    first_pass = False
                    self._register_last_ack_date(now)
                for s in ready_to_read:
                    if fbk_lengths[s] is None:
                        sz = NetworkTarget.CHUNK_SZ
                    else:
                        sz = min(fbk_lengths[s] - bytes_recd[s], NetworkTarget.CHUNK_SZ)

                    retry = 0
                    socket_timed_out = False
                    while retry < 3:
                        try:
                            chunk = s.recv(sz)
                        except socket.timeout:
                            chunk = b''
                            socket_timed_out = True  # for UDP we keep the socket
                            break
                        except socket.error as serr:
                            chunk = b''
                            print('\n*** ERROR[{!s}] (while receiving): {:s}'.format(
                                serr.errno, str(serr)))
                            if serr.errno == socket.errno.EAGAIN:
                                retry += 1
                                time.sleep(2)
                                continue
                            else:
                                break
                        else:
                            break

                    if chunk == b'':
                        print('\n*** NOTE: Nothing more to receive from: {!r}'.format(fbk_ids[s]))
                        fbk_sockets.remove(s)
                        _check_and_handle_obsolete_socket(s)
                        if not socket_timed_out:
                            s.close()
                        continue
                    else:
                        bytes_recd[s] = bytes_recd[s] + len(chunk)
                        chunks[s].append(chunk)

                has_read = True


            if fbk_sockets:
                for s in fbk_sockets:
                    if s in ready_to_read:
                        s_fbk_len = fbk_lengths[s]
                        if s_fbk_len is None or bytes_recd[s] < s_fbk_len:
                            dont_stop = True
                            break
                    else:
                        dont_stop = True
                        break
                else:
                    dont_stop = False

                if duration > fbk_timeout or (has_read and not self.fbk_wait_full_time_slot_mode):
                    dont_stop = False

            else:
                dont_stop = False

        for s, chks in chunks.items():
            fbk = b'\n'.join(chks)
            with self._fbk_handling_lock:
                fbkid = fbk_ids[s]
                fbk, err = self._feedback_handling(fbk, fbkid)
                self._feedback_collect(fbk, fbkid, error=err)
                if (self._additional_fbk_sockets is None or s not in self._additional_fbk_sockets) and \
                        (self._hclient_sock2hp is None or s not in self._hclient_sock2hp.keys()) and \
                        (self._last_client_sock2hp is None or s not in self._last_client_sock2hp.keys()):
                    s.close()

        with self._fbk_handling_lock:
            for fbkid, ev in socket_errors:
                self._feedback_collect(">>> ERROR[{:d}]: unable to interact with '{:s}' "
                                       "<<<".format(ev,fbkid), fbkid, error=-ev)
            if from_fmk:
                self._feedback_complete(send_id)

        return


    def _send_data(self, s, data_refs, sid, from_fmk, pre_fbk=None, iface='eth0'):
        if sid != self._initial_sending_id:
            self._initial_sending_id = sid
#             self._first_send_data_call = True


        if self._first_send_data_call:
            self._first_send_data_call = False

#             fbk_sockets, fbk_ids, fbk_lengths = self._get_additional_feedback_sockets()
#             if fbk_sockets:
#                 for fd in fbk_sockets:
#                     epobj.register(fd, select.EPOLLIN)
#                     fileno2fd[fd.fileno()] = fd
        else:
            fbk_sockets, fbk_ids, fbk_lengths = None, None, None

#         if data_refs[s[0]][0] is None:
#             # We check the data to send. If it is None, we only collect feedback from the sockets.
#             # This is used by self.collect_feedback_without_sending()
#             if fbk_sockets is None:
#                 assert fbk_ids is None
#                 assert fbk_lengths is None
#                 fbk_sockets = []
#                 fbk_ids = {}
#                 fbk_lengths = {}
# 
#             for s in sockets:
#                 data, host, port, address = data_refs[s]
#                 epobj.register(s, select.EPOLLIN)
#                 fileno2fd[s.fileno()] = s
#                 fbk_sockets.append(s)
#                 fbk_ids[s] = self._default_fbk_id[(host, port)]
#                 fbk_lengths[s] = self.feedback_length
# 
#             self._start_fbk_collector(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd, from_fmk,
#                                       pre_fbk=pre_fbk)
# 
        print(len(s[0]))
        print(s)
        sendp(s, iface=iface, verbose=True)


    def _start_fbk_collector(self, fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd, from_fmk,
                             pre_fbk=None):
        self._thread_cpt += 1
        if from_fmk:
            self.feedback_thread_qty += 1
        feedback_thread = threading.Thread(None, self._collect_feedback_from,
                                           name='FBK-' + repr(self._sending_id) + '#' + repr(self._thread_cpt),
                                           args=(fbk_sockets, fbk_ids, fbk_lengths, epobj, fileno2fd,
                                                 self._sending_id, self._feedback_timeout, from_fmk,
                                                 pre_fbk))
        feedback_thread.start()

    def _feedback_collect(self, fbk, ref, error=0):
        if error < 0:
            self._feedback.set_error_code(error)
        self._feedback.add_fbk_from(ref, fbk, status=error)

    def _feedback_complete(self, sid):
        # print('\n***DBG1:', self.feedback_complete_cpt, self.feedback_thread_qty,
        #       'sending_id=', self._sending_id, sid)
        if sid == self._sending_id:
            self.feedback_complete_cpt += 1
            if self.feedback_complete_cpt == self.feedback_thread_qty:
                self._feedback_handled = True
        # print('\n***DBG2:', self.feedback_complete_cpt, self.feedback_thread_qty)

    def _before_sending_data(self, data_list, from_fmk):
        if from_fmk:
            self._last_ack_date = None
            self._first_send_data_call = True  # related to additional feedback
            with self._fbk_handling_lock:
                self._sending_id += 1
                self._feedback_handled = False
        else:
            self._first_send_data_call = False  # we ignore all additional feedback

        if data_list is None:
            return

        if isinstance(data_list, Data):
            data_list = [data_list]

        for data in data_list:
            if not isinstance(data.content, Node):
                continue
            data.content.freeze()

        self._custom_data_handling_before_emission(data_list)


    def collect_feedback_without_sending(self):
        self.send_multiple_data(None, from_fmk=True)
        return True

    def get_feedback(self):
        return self._feedback

    def is_target_ready_for_new_data(self):
        # We answer we are ready if at least one receiver has
        # terminated its job, either because the target answered to
        # it, or because of the current specified timeout.
        # TODO LAYER 2 IS ALREADY READY FOR DATA?
        return True
    
#         if self._feedback_handled:
#             return True
#         else:
#             return False

    def _register_last_ack_date(self, ack_date):
        self._last_ack_date = ack_date

    def get_last_target_ack_date(self):
        return self._last_ack_date

    def _get_socket_type(self, host, port):
        for key, h in self._host.items():
            if h == host and self._port[key] == port:
                st = self._socket_type[key]
                if st[:2] == (socket.AF_INET, socket.SOCK_STREAM):
                    return 'STREAM'
                elif st[:2] == (socket.AF_INET, socket.SOCK_DGRAM):
                    return 'DGRAM'
                elif st[:2] == (socket.AF_PACKET, socket.SOCK_RAW):
                    return 'RAW'
                else:
                    return repr(st)
        else:
            return None

    def get_description(self):
        
        desc = ''
        
        for key, host in self.targetInfo.items():
            
            desc += '{:s}:{:d}'.format(host['TargetIP'], host['TargetPort'])

#             desc += '{:s}:{:d}#{!s} (serv:{!r},hold:{!r}), '.format(
#                 host, port, socket_type, server_mode, hold_connection)


        return desc