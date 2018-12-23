# encoding='utf-8'
import socket
import threading
import queue
import time
import select
from MySocketPro import *

HOST = '127.0.0.1'
PORT = 8134

class Server(threading.Thread):
    """
    Server Implement
    """
    def __init__(self, host, port):
        super().__init__(daemon=True, target=self.run)
        # socket of server
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # get local machine name
        self.port = port
        self.host = host

        # define the size of buffer
        self.buffer_size = 2048

        # define dicts
        # 1. msg_queues: used as write buffer
        # key: client_socket  value: queue of message
        # sent by client_sock.send()
        self.msg_queues = {}

        # 2. login_dict
        # key: user name    value: client_socket
        self.login_dict = {}

        # define lists
        # record all connection sockets
        self.connection_list = []

        # define lock of thread
        self.lock = threading.RLock()

        # socket setup
        self.shutdown = False

        try:
            # bind to the port and IP address
            self.server_socket.bind((str(self.host), int(self.port)))

            # maximum number for TCP connections
            self.server_socket.listen(5)

            # start the server thread
            self.start()
        except socket.error:
            print('Socket Error')
            self.shutdown = True

        # main loop
        while not self.shutdown:
            # waiting for cmd
            cmd = input('>>>\n')
            if cmd == 'quit':
                for sock in self.connection_list:
                    sock.close()
                self.shutdown = True
                self.server_socket.close()

    def remove_user(self, user, user_socket):
        with self.lock:
            if user in self.login_dict:
                del self.login_dict[user]
            if user_socket in self.connection_list:
                self.connection_list.remove(user_socket)
            if user_socket in self.msg_queues:
                del self.msg_queues[user_socket]

    def run(self):
        print("Server is running.\n")
        while True:
            with self.lock:
                try:
                    # waiting until connection arrives.
                    client_socket, addr = self.server_socket.accept()
                except socket.error:
                    time.sleep(0.1)
                    continue

                print("Got a connection from {}".format(addr))
                print("Socket connects {} and {}".format(client_socket.getsockname(), client_socket.getpeername()))

                # setup connection
                if client_socket not in self.connection_list:
                    self.connection_list.append(client_socket)
                self.msg_queues[client_socket] = queue.Queue()
                ClientThread(self, client_socket, addr)


class ClientThread(threading.Thread):
    """Thread for each connection"""
    def __init__(self, master, client_socket, address):
        super().__init__(daemon=True, target=self.run)
        self.master = master
        self.client_socket = client_socket
        self.address = address
        self.buffer_size = 2048

        # user name
        self.login_user = ''
        self.inputs = []
        self.outputs = []

        self.start()

    def run(self):
        """Main method for client thread processing client socket"""
        # print("New thread started for connection from {}".format(self.address))
        self.inputs = [self.client_socket]
        self.outputs = [self.client_socket]
        while self.inputs:
            try:
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            except select.error:
                self.disconnect()
                break

            if self.client_socket in readable:
                try:
                    data = self.client_socket.recv(self.buffer_size)
                except socket.error:
                    self.disconnect()
                    break

                shutdown = self.process_recv_data(data)
                if shutdown:
                    self.disconnect()
                    break

            if self.client_socket in writable:
                with self.master.lock:
                    if not self.master.msg_queues[self.client_socket].empty():
                        data = self.master.msg_queues[self.client_socket].get()
                        try:
                            self.client_socket.sendall(data)
                        except socket.error:
                            self.disconnect()
                            break

            if self.client_socket in exceptional:
                self.disconnect()
                break

    def __broadcast(self, msg):
        with self.master.lock:
            for client_sock, client_queue in self.master.msg_queues.items():
                client_queue.put(msg)

    def update_client_list(self):
        """Tell all users that client list has changed"""
        print("Update client list.")
        # used by GUI
        clients = ' '.join([user for user in self.master.login_dict.keys()])
        msg = make_protocol_msg(method='UPDATE', from_who=self.login_user, agent='server.py', message=clients)
        self.__broadcast(msg)

    def disconnect(self):
        """Disconnect from sercer"""
        with self.master.lock:
            print("Client {} has disconnected".format(self.login_user))
            # remove related info from server
            self.master.remove_user(self.login_user, self.client_socket)
            self.client_socket.close()
            self.update_client_list()

    def process_recv_data(self, data):
        if data is None or data == '':
            return True

        shutdown = False
        # data: utf-8
        #try:
        #    data = data.encode('gbk')
        #except UnicodeDecodeError:
        #    print("Error: Unicode Decode Error.")

        print('Server receives: ', end=' ')
        print(data.decode('utf-8').encode('gbk'))

        recv_dict = analyze_protocol_msg(data.decode('utf-8'))

        print("Protocol Analyze: ", end=' ')
        print(recv_dict)
        if recv_dict['method'] == 'LOGIN':
            if recv_dict['from_who'] in self.master.login_dict:
                message = make_protocol_msg('USERILL', 'SERVER', 'server.py')
                self.client_socket.sendall(message)
            else:
                # setup connection for Server
                #with self.master.lock:
                print("{} login. ".format(recv_dict['from_who']))
                #if self.client_socket not in self.master.connection_list:
                #    self.master.connection_list.append(self.client_socket)
                self.login_user = recv_dict['from_who']
                self.master.login_dict[self.login_user] = self.client_socket
                #self.master.msg_queues[self.client_socket] = queue.Queue()
                # send login success message
                message = make_protocol_msg('LOGIN', 'SERVER', 'server.py')
                self.client_socket.sendall(message)
                self.update_client_list()

        elif recv_dict['method'] == 'PUBLIC':
            message = recv_dict['message']
            print('message broadcast: {}'.format(message))
            with self.master.lock:
                message = make_protocol_msg('PUBLIC', self.login_user, 'server.py', message)
                self.__broadcast(message)

        elif recv_dict['method'] == 'PRIVATE':
            to_user = recv_dict['WITH']
            from_user = self.login_user
            try:
                with self.master.lock:
                    if to_user in self.master.login_dict:
                        sock = self.master.login_dict[to_user]
                        message = recv_dict['message']
                        print("message from {} sent to {}: {}".format(from_user, to_user, message))
                        message = make_protocol_msg(method='PRIVATE', from_who=from_user, agent='server.py',
                                                    message=message, list=[('WITH', to_user)])
                        self.master.msg_queues[sock].put(message)
            except socket.error:
                print('Socket Error!')
        elif recv_dict['method'] == 'LOGINOUT':
            shutdown = True
        else:
            print('Illegal Method')
        return shutdown


# Create New Server
if __name__ == '__main__':
    server = Server(HOST, PORT)