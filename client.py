import socket
import threading
import time
import queue
import select
from Gui import *
from MySocketPro import *

HOST = '127.0.0.1'
PORT = 8134

class Client(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=True, target=self.run)

        # info of server
        self.host = host
        self.port = port
        # info of client
        self.client_socket = None
        self.buffer_size = 2048

        self.inputs = []
        self.outputs = []

        # write buffer
        self.queue = queue.Queue()

        # name of user
        self.username = ''

        # check whether login
        self.isLogin = False
        # check whether connected
        self.isConnected = False

        # define lock of thread
        self.lock = threading.RLock()

        self.gui = GUI(self)
        self.gui.start()
        if not self.isConnected:
            self.isConnected = self.connect_to_server()
        if self.isConnected:
            self.start()


    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
        except ConnectionRefusedError:
            print('Inactive server, fail to connect.')
            return False

        # Connect Successfully
        return True

    def run(self):
        self.inputs = [self.client_socket]
        self.outputs = [self.client_socket]
        while self.inputs:
            try:
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            except ValueError:
                print("Server Error")
                GUI.display_alert("Server error. Exit. ")
                self.client_socket.close()
                break

            if self.client_socket in readable:
                with self.lock:
                    try:
                        data = self.client_socket.recv(self.buffer_size).decode()
                    except socket.error:
                        print('Socket error in receiving message')
                        self.gui.display_alert('Socket error. Exit.')
                        self.client_socket.close()
                        break
                if len(data) != 0:
                    self.process_recv_msg(data)
                else:
                    print("Server Error!")
                    self.gui.display_alert("Server error. Exit. ")
                    self.client_socket.close()
                    break

            if self.client_socket in writable:
                try:
                    if not self.queue.empty():
                        data = self.queue.get()
                        self.send(data)
                        self.queue.task_done()
                    else:
                        time.sleep(0.01)
                except socket.error:
                    print('Socket error in reading')
                    self.gui.display_alert('Socket error. Exit.')
                    self.client_socket.close()
                    break

            if self.client_socket in exceptional:
                print("Server Error!")
                self.gui.display_alert("Server error. Exit. ")
                self.client_socket.close()
                break

    def send(self, msg):
        with self.lock:
            try:
                print("Send Message: {}".format(msg))
                self.client_socket.sendall(msg.encode())
            except socket.error:
                self.client_socket.close()
                GUI.display_alert('client failed to send. Exit.')

    def notify_server(self, user, method):
        """use for login or logout"""
        print("client notifies server: {} {}".format(user, method))
        with self.lock:
            # connect to server
            #if not self.isConnected:
            #    self.isConnected = self.connect_to_server()
            #    if not self.isConnected:
            #        self.gui.display_alert('Inactive server, fail to connect.')
            #        return

            message = make_protocol_msg(method=method, from_who=user)
            self.send(message)
            #self.queue.put(message)

            if method == "LOGOUT":
                self.clear_queue()
                self.client_socket.close()

    def clear_queue(self):
        """ Clear queue by sending all messages"""
        with self.lock:
            while not self.queue.empty():
                data = self.queue.get()
                self.send(data)

    def process_recv_msg(self, data):
        """deal with the message received"""
        print("Client receives: ", end=' ')
        print(data)

        recv_dict = analyze_protocol_msg(data)

        if recv_dict['method'] == "USERILL" and (not self.isLogin):
            self.username = ''
            print("Username has been used.\nPlease try another one.")
            self.gui.display_alert("Username has been used.\nPlease try another one.")

        elif recv_dict['method'] == 'LOGIN' and (not self.isLogin):
            self.isLogin = True

            # close LoginWindow
            self.gui.login_window.root.quit()

        elif recv_dict['method'] == "UPDATE":
            active_users = recv_dict['message']
            print('Update login list: {}'.format(active_users))
            self.gui.update_login_list(active_users)

        elif recv_dict['method'] == "PUBLIC":
            message = recv_dict['message']
            senter = recv_dict['from_who']
            time_tag = time.asctime(time.localtime(time.time()))

            head = senter + "\t>>>\t"
            head = head + ' '*(60-len(head)) + time_tag
            message = head + '\n' + message
            if message[-1] != '\n':
                message += '\n'
            self.gui.main_window.display_message(message, senter)

        elif recv_dict['method'] == "PRIVATE":
            return



if __name__ == '__main__':
    client = Client(HOST, PORT)