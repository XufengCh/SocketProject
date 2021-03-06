# encoding='gbk'
import socket
import threading
from MySocketPro import *

HOST = '127.0.0.1'
PORT = 8134

class Server:
    """
    server implement
    """
    def __init__(self, host, port, max=10):
        # host and port
        self.host = host
        self.port = port
        # server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # key: user name
        # value: conn socket
        self.__user_dict = {}
        self.__max = max
        self.__count = 0

    def __broadcast(self, data):
        """
        send data to all login_user
        data: str
        """
        for user, conn in self.__user_dict.items():
            print("Send to {} :\t{}".format(user, data))
            conn.sendall(data.encode())

    def update_client_list(self):
        """
        Tell all users that client list has changed
        """
        print("Update client list.")
        # used by GUI
        clients = ' '.join([user for user in self.__user_dict.keys()])
        msg = make_protocol_msg(method='UPDATE', from_who="SERVER", message=clients)
        self.__broadcast(msg)

    def process_recv_message(self, username):
        print("{} join the chat".format(username))
        connection = self.__user_dict[username]
        #connection.settimeout(50)
        while True:
            try:
                data = connection.recv(1024).decode()
                print("{} sent: {}".format(username, data))
                recv_dict = analyze_protocol_msg(data)
                if recv_dict['method'] == "PUBLIC":
                    self.__broadcast(data)
                elif recv_dict['method'] == "PRIVATE":
                    with_whom = recv_dict['WITH']
                    self.__user_dict[with_whom].sendall(data.encode())
                elif recv_dict['method'] == "LOGOUT":
                    del self.__user_dict[username]
                    self.__count -= 1
                    connection.close()
                    self.update_client_list()
                    print("{} left chatroom. ".format(username))
                    break
                #else:
                #    raise ValueError("Illegal Method: " + recv_dict['method'])
            except ValueError as ve:
                print(ve)
            except ConnectionResetError:
                print("Error: {} connection reset.".format(username))
                del self.__user_dict[username]
                self.__count -= 1
                connection.close()
                self.update_client_list()

    def start(self):
        # socket bind
        self.server_socket.bind((self.host, self.port))
        # listen
        self.server_socket.listen(self.__max)
        print('Chatroom Server Is Ready!\n')
        while True:
            try:
                conn, addr = self.server_socket.accept()

                # if self.__count >= self.__max:
                #     message=make_protocol_msg(method="FULL", from_who="SERVER")
                #     conn.sendall(message.encode())
                #     raise ValueError("Chatroom is FULL. ")
                # create connection
                print("New connection has been set...")
                # Now try to login
                print("Now try to login...")
                data = str(conn.recv(1024).decode())
                recv_dict = analyze_protocol_msg(data)
                if recv_dict['method'] == "LOGIN":
                    # full
                    if self.__count >= self.__max:
                        message = make_protocol_msg(method="FULL", from_who="SERVER")
                        conn.sendall(message.encode())
                        raise ValueError("Chatroom is FULL. ")
                    # illegal username
                    login_name = recv_dict['from_who']
                    if login_name not in self.__user_dict:
                        # login success
                        self.__user_dict[login_name] = conn
                        self.__count +=1
                        # send LOGIN message
                        clients = ' '.join([user for user in self.__user_dict.keys()])
                        login_msg = make_protocol_msg(method="LOGIN", from_who="SERVER", message=clients)
                        conn.sendall(login_msg.encode())
                        # update login list
                        self.update_client_list()
                        client_thread = threading.Thread(target=self.process_recv_message, args=(login_name, ), daemon=True)
                        client_thread.start()
                    else:
                        # send USERILL message
                        conn.sendall(make_protocol_msg(method="USERILL", from_who="SERVER").encode())
                        conn.close()
                        raise ValueError("User name has been used. ")
            except ConnectionError:
                for user, conn in self.__user_dict.items():
                    conn.sendall(make_protocol_msg("CLOSE", "SERVER").encode())
                    conn.close()
                self.__user_dict = {}
                print("Something wrong with connection. Chatroom shutdown. ")
            except ValueError as ve:
                print("Error: ", end=' ')
                print(ve)

if __name__ == '__main__':
    server = Server(HOST, PORT)
    server.start()

