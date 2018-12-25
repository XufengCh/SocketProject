import threading
import socket
import time
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

from MySocketPro import *

HOST = '127.0.0.1'
PORT = 8134

class Client:
    def __init__(self, host, port):
        # host and port
        self.__host = host
        self.__port = port

        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_login = False
        self.username = None

        # GUI windows
        #self.login_window = LoginWindow(self)
        #threading.Thread(target=self.login_window.mainloop, daemon=True).start()
        self.login_window = LoginWindow(self)
        self.main_window = None
        self.private_window_dict = {}

        self.start_login_flag = False

    def run(self):
        # create login_window thread
        #threading.Thread(target=self.create_login_window, daemon=True).start()
        self.create_login_window()
        # watch start_login_flag
        while not self.start_login_flag:
            pass
        self.login()

    def create_login_window(self):
        #self.login_window = LoginWindow(self)
        self.login_window.mainloop()

    def create_main_window(self):
        self.main_window = PublicChatWindow(self)
        self.main_window.mainloop()

    def create_private_window(self, private_name):
        try:
            if private_name not in self.private_window_dict:
                private_window = PrivateChatWindow(self, private_name)
                self.private_window_dict[private_name] = private_window
                private_window.mainloop()
        except KeyError:
            pass

    @staticmethod
    def display_alert(message):
        """Display alert box"""
        messagebox.showinfo('Error: ', message)

    def send_message_thread(self, message):
        print("Send Success")
        self.__socket.sendall(message.encode())

    def send_message(self, message):
        threading.Thread(target=self.send_message_thread, args=(message, ), daemon=True).start()

    def logout(self):
        # exit
        self.is_login = False

        if self.main_window:
            self.main_window.destory()

        for user, private in self.private_window_dict.items():
            del self.private_window_dict[user]
            private.destory()
        self.private_window_dict = {}
        message = make_protocol_msg(method="LOGOUT", from_who=self.username)
        self.send_message(message)

        self.__socket.close()

    def start_private_chat_with(self, private_name):
        if private_name in self.private_window_dict:
            return
        if private_name == self.username:
            return
        # create private chat window
        #private_window = PrivateChatWindow(self, private_name)
        #self.private_window_dict[private_name] = private_window
        #threading.Thread(target=self.create_private_window, args=(private_name, ), daemon=True).start()
        self.create_private_window(private_name)

    def exit_private_chat(self, private_name):
        try:
            if private_name in self.private_window_dict:
                #self.private_window_dict[private_name].destroy()
                del self.private_window_dict[private_name]
        except KeyError:
            print("Private chat with {} has already exited. ")

    def receive_message_thread(self):
        while self.is_login:
            try:
                data = self.__socket.recv(1024).decode()
                print("Socket Received...")
                recv_dict = analyze_protocol_msg(data)
                if recv_dict['method'] == "PUBLIC":
                    time_tag = time.asctime(time.localtime(time.time()))
                    message = recv_dict['from_who'] + '\t>>>\t'
                    message += ' '*(25-len(message)) + time_tag
                    message += '\n'+recv_dict['message']
                    if message[-1] != '\n':
                        message += '\n'
                    self.main_window.display_message(message)

                elif recv_dict['method'] == 'PRIVATE':
                    time_tag = time.asctime(time.localtime(time.time()))
                    message = recv_dict['from_who'] + '\t>>>\t'
                    message += ' ' * (25 - len(message)) + time_tag
                    message += '\n' + recv_dict['message']
                    if message[-1] != '\n':
                        message += '\n'
                    self.main_window.display_message(message)

                    # private name
                    try:
                        private_name = recv_dict['WITH']
                        self.start_private_chat_with(private_name)
                        self.private_window_dict[private_name].display_message(message)
                    except KeyError:
                        print("Wrong private chat message.")

                elif recv_dict['method'] == "UPDATE":
                    active_users = recv_dict['message']
                    print("Update login list: {}".format(active_users))
                    clients = []
                    index = 0
                    while active_users != '' and data[0] != ' ' and data[0] != '\n':
                        index = active_users.find(' ')
                        if index != -1:
                            name = data[0:index]
                            clients.append(name)
                            if len(data[index:]) > 1:
                                data = data[index + 1:]
                            else:
                                data = ''
                        else:
                            break
                    if data != '' and data != ' ' and data[0] != '\n':
                        clients.append(data)
                    self.main_window.update_login_list(clients)

                elif recv_dict['method'] == "CLOSE":
                    self.logout()
            except socket.error:
                print("Client error. Exit")
                messagebox.showinfo("Error", "Client error. Exit")
                self.logout()
        self.logout()

    def login(self):
        #self.username = username
        errorlog = ''
        try:
            self.__socket.connect((self.__host, self.__port))
            send_message = make_protocol_msg(method="LOGIN", from_who=self.username)
            self.__socket.sendall(send_message.encode())
            data = self.__socket.recv(1024).decode()
            recv_dict = analyze_protocol_msg(data)
            if recv_dict['method'] == 'FULL':
                errorlog = "[Server] Chatroom is full. "
                raise ValueError("[Server] Chatroom is full. ")
            elif recv_dict['method'] == 'USERILL':
                errorlog = "[Server] Username has been used."
                raise ValueError("[Server] Username has been used.")
            elif recv_dict['method'] == 'LOGIN':
                self.is_login = True

                # create main_window
                #self.main_window = PublicChatWindow(self)
                #threading.Thread(target=self.main_window.run, daemon=True).start()
                #threading.Thread(target=self.create_main_window, daemon=True).start()
                self.create_main_window()

                # create receive thread
                threading.Thread(target=self.receive_message_thread, daemon=True).start()

                # destroy login_window
                self.login_window.destroy()

        except ValueError as ve:
            self.display_alert(errorlog)
            self.is_login = False
            print(ve)
            self.username = ''
            self.__socket.close()
            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class LoginWindow(tk.Tk):
    def __init__(self, client):
        tk.Tk.__init__(self)
        self.client = client

        #self.title = "Start Chatting"
        self.title("Start Chatting...")

        # font
        self.font = ("consolas", 12)

        self.geometry("300x100")

        # frame0
        self.frame0 = tk.Frame(self)
        self.label0 = tk.Label(self.frame0, text="Welcome to Tony's Chatroom",
                               font=("consolas", 12))
        self.label0.pack()
        self.frame0.pack(side=tk.TOP)

        # frame1
        self.frame1 = tk.Frame(self)

        self.label1 = tk.Label(self.frame1, text="Your Name: ", font=self.font)
        self.label1.pack(side=tk.LEFT)

        self.entry_name = tk.Entry(self.frame1, width=15, font=self.font)
        self.entry_name.pack(side=tk.RIGHT, expand=tk.YES)
        self.entry_name.bind('<KeyRelease-Return>', self.get_login_event)

        self.frame1.pack(padx=5, pady=5)

        # frame2
        self.frame2 = tk.Frame(self)

        self.button = tk.Button(self.frame2, text="Login", width=15, font=self.font)
        self.button.pack(side=tk.RIGHT)
        self.button.bind('<Button-1>', self.get_login_event)

        self.frame2.pack(padx=5, pady=4)

        self.mainloop()

    def get_login_event(self, event=None):
        if self.client.is_login:
            return
        login = self.entry_name.get()
        if login == None or login == '' or login == '\n':
            self.client.display_alert("Illegal User Name!")
            return
        index = str(login).find(' ')
        if index != -1:
            self.client.display_alert("There can be <Space> in username!")
            return
        if len(login) > 10:
            self.client.display_alert("User name is too long. ")
            return
        #self.client.login(username=login)

        #connect_thread = threading.Thread(target=self.client.login, args=(login, ), daemon=True)
        #connect_thread.start()
        self.client.username = login
        self.client.start_login_flag = True

    def run(self):
        self.mainloop()

class ChatWindow(tk.Tk):
    def __init__(self, client):
        tk.Tk.__init__(self)
        self.client = client
        self.font = ("consolas", 12)

        # GUI
        # window size
        self.geometry('750x450')
        self.resizable(0, 0)

        main_frame = tk.Frame(self)

        # Listbox widget for displaying active users and selecting them
        self.login_list = tk.Listbox(main_frame, width=15, height=20, selectmode=tk.SINGLE, font=self.font,
                                    foreground='black', selectbackground='#DCDCDC')
        self.login_list.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        #self.login_list.bind("<Double-Button-1>", self.start_private_chat)

        # ScrolledText widget for displaying messages
        self.message_window = scrolledtext.ScrolledText(main_frame, wrap='word', font=self.font,
                                                        width=60, height=15, undo=True)
        self.message_window.insert(tk.END, 'Start Chatting !\n\n')
        self.message_window.configure(state='disabled')
        self.message_window.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="nsew")

        # Entry widget for typing messages in
        self.entry_text = tk.Text(main_frame, width=45, height=5, undo=True, font=self.font)
        self.entry_text.focus_set()
        self.entry_text.bind('<KeyRelease-Return>', self.send_entry_event)
        self.entry_text.grid(row=1, column=1, rowspan=2, padx=10, pady=10, sticky="nsew")

        # Butron widgets
        button_frame = tk.Frame(main_frame)
        self.send_button = tk.Button(button_frame, text="SEND", width=10, height=1, bg="#A9A9A9", font=("consolas", 12))
        self.send_button.bind('<Button-1>', self.send_entry_event)
        self.send_button.pack(side=tk.TOP, padx=15, pady=10)

        self.exit_button = tk.Button(button_frame, text="EXIT", width=10, height=1, bg="#A9A9A9", font=("consolas", 12))
        self.exit_button.bind('<Button-1>', self.exit_event)
        self.exit_button.pack(side=tk.BOTTOM, padx=15, pady=10)
        button_frame.grid(row=1,column=2, rowspan=2, sticky="nsew")

        main_frame.pack()

    def run(self):
        self.mainloop()
        self.destroy()

    def display_message(self, message):
        self.message_window.configure(state='normal')
        self.message_window.insert(tk.END, message)
        self.message_window.configure(state='disabled')
        self.message_window.see(tk.END)

    def send_entry_event(self, event=None):
        text = self.entry_text.get(1.0, tk.END)
        if text != '\n':
            message = text[:-1]
            self.send_message(message)
            self.entry_text.mark_set(tk.INSERT, 1.0)
            self.entry_text.delete(1.0, tk.END)
            self.entry_text.focus_set()
        #else:
            #messagebox.showinfo('Warning', 'You must enter non-empty message')

    def send_message(self, message):
        # detailed implement required later
        return

    def exit_event(self, event=None):
        # detailed implement required later
        return

class PublicChatWindow(ChatWindow):
    def __init__(self, client):
        super().__init__(client)
        self.title("Chatroom ---- User: " + self.client.username)
        self.login_list.bind("<Double-Button-1>", self.start_private_chat)
        self.mainloop()
    def send_message(self, message):
        print("Public Chat Window Sent: {}".format(message))
        method = "PUBLIC"
        send_text = make_protocol_msg(method=method, from_who=self.client.username, message=message)
        self.client.send_message(send_text)

    def exit_event(self, event=None):
        self.client.is_login = False
        self.destroy()

    def update_login_list(self, active_users):
        self.login_list.delete(0, tk.END)
        for user in active_users:
            self.login_list.insert(tk.END, user)
        self.login_list.select_set(0)

    def start_private_chat(self, event=None):
        receiver_name = self.login_list.get(self.login_list.curselection())
        self.client.start_private_chat_with(receiver_name)

class PrivateChatWindow(ChatWindow):
    def __init__(self, client, private_name):
        super().__init__(client)
        self.private_name = private_name
        self.title("Private Chat With:\t" + private_name)
        self.login_list.delete(0, tk.END)
        self.login_list.insert(tk.END, self.client.username)
        self.login_list.insert(tk.END, private_name)
        self.mainloop()
    def send_message(self, message):
        print("Private send to {}:\t{}".format(self.private_name, message))
        method = "PRIVATE"
        send_text = make_protocol_msg(method=method, from_who=self.client.username, message=message,
                                      list=[("WITH", self.private_name)])
        self.client.send_message(send_text)

    def exit_event(self, event=None):
        self.client.exit_private_chat(self.private_name)
        self.destroy()

if __name__ == '__main__':
    client = Client(HOST, PORT)
    client.run()
