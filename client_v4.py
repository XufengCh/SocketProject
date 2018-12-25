import threading
import socket
import time
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

from MySocketPro import *

HOST = '127.0.0.1'
PORT = 8134

login_frame = 'login_frame'
main_frame = 'main_frame'

class Client(tk.Tk):
    def __init__(self, host, port):
        tk.Tk.__init__(self)
        # client info
        self.host = host
        self.port = port
        self.username = ''
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_login = False

        # use for GUI
        self.resizable(False, False)
        container = tk.Frame(self)
        container.pack(side='top', fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # use dict to manage frames
        self.frames = {}

        # login frame
        self.frames[login_frame] = LoginFrame(self, container)
        # Chat frame
        self.frames[main_frame] = ChatFrame(self, container)

        self.display_frame(login_frame)

    def display_frame(self, frame_name):
        for frame in self.frames.values():
            frame.grid_remove()
        try:
            frame = self.frames[frame_name]
            frame.grid(row=0, column=0, sticky='ewsn')
            frame.tkraise()
            print("Raise Frame: {}".format(frame_name))
        except KeyError:
            print("No such frame in client. ")

    @staticmethod
    def display_alert(message):
        """Display alert box"""
        messagebox.showinfo('Error: ', message)

    def get_client_frame(self, frame_name):
        try:
            frame = self.frames[frame_name]
            return frame
        except KeyError:
            print("{} Not Found. ".format(frame_name))
            return None

    def exit_client(self):
        self.is_login = False
        self.client_socket.close()
        self.destroy()

    def send_message(self, message):
        try:
            self.client_socket.sendall(message.encode())
        except socket.error:
            self.display_alert("Socket Error. ")
            self.exit_client()

    def receive_message(self):
        while self.is_login:
            try:
                data = self.client_socket.recv(1024).decode()
                recv_dict = analyze_protocol_msg(data)
                if recv_dict['method'] == "PUBLIC":
                    time_tag = time.asctime(time.localtime(time.time()))
                    message = recv_dict['from_who'] + '\t>>>\t'
                    message += ' '*(25-len(message)) + time_tag
                    message += '\n'+recv_dict['message']
                    if message[-1] != '\n':
                        message += '\n'
                    if recv_dict['from_who'] == self.username:
                        self.get_client_frame(main_frame).display_message(message, True)
                    else:
                        self.get_client_frame(main_frame).display_message(message)

                elif recv_dict['method'] == "UPDATE":
                    active_users = recv_dict['message']
                    print("Update login list: {}".format(active_users))
                    self.get_client_frame(main_frame).update_login_list(active_users)

                elif recv_dict['method'] == "CLOSE":
                    print("Server Close. ")
                    self.exit_client()
            except KeyError:
                print("KeyError Received. ")
            except socket.error:
                print("Socket Error. ")
                self.display_alert("Server has closed. ")
                self.exit_client()


    def login_client(self, username):
        self.username = username
        errorlog = ''
        try:
            self.client_socket.connect((self.host, self.port))
            msg = make_protocol_msg(method='LOGIN', from_who=self.username)
            self.client_socket.sendall(msg.encode())
            data = self.client_socket.recv(1024).decode()
            recv_dict = analyze_protocol_msg(data)
            if recv_dict['method'] == 'FULL':
                errorlog = "[Server] Chatroom is full. "
                raise ValueError
            elif recv_dict['method'] == 'USERILL':
                errorlog = "[Server] Username has been used."
                raise ValueError
            elif recv_dict['method'] == 'LOGIN':
                # login success
                self.is_login = True
                # display ChatFrame
                self.display_frame(main_frame)
                self.get_client_frame(main_frame).update_login_list(recv_dict['message'])

                # start receive_message thread
                threading.Thread(target=self.receive_message, daemon=True).start()
        except ValueError:
            print(errorlog)
            self.display_alert(errorlog)
            self.username = ''
            self.client_socket.close()
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



class LoginFrame(tk.Frame):
    def __init__(self, client, up_frame):
        super().__init__(up_frame)
        self.client = client

        # design GUI ---- login frame
        # font
        self.font = ("consolas", 12)

        #self.geometry("300x100")

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

    def get_login_event(self, event=None):
        username = self.entry_name.get()
        if len(username) == 0 or username == '\n':
            self.client.display_alert("Please enter your name. ")
            return
        if len(username) > 10:
            self.client.display_alert("User name must be shorter than 10 characters. ")
            return
        index = username.find(' ')
        if index != -1:
            self.client.display_alert("Space is not permitted in username")
            return

        threading.Thread(target=self.client.login_client, args=(username, ), daemon=True).start()

class ChatFrame(tk.Frame):
    def __init__(self, client, up_frame):
        super().__init__(up_frame)
        self.client = client

        # font
        self.font = ("consolas", 12)

        # GUI
        # window size
        #self.geometry('750x450')

        main_frame = tk.Frame(self)

        # Listbox widget for displaying active users and selecting them
        self.login_list = tk.Listbox(main_frame, width=15, height=20, selectmode=tk.SINGLE, font=self.font,
                                     selectbackground='#DCDCDC')
        self.login_list.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        # self.login_list.bind("<Double-Button-1>", self.start_private_chat)

        # ScrolledText widget for displaying messages
        self.message_window = scrolledtext.ScrolledText(main_frame, wrap='word', font=self.font,
                                                        width=60, height=15, undo=True)
        self.message_window.insert(tk.END, 'Start Chatting !\n\n')
        self.message_window.configure(state='disabled')
        self.message_window.tag_config('me', foreground="#8470FF")
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
        button_frame.grid(row=1, column=2, rowspan=2, sticky="nsew")

        main_frame.pack()

    def send_entry_event(self,event=None):
        text = self.entry_text.get(1.0, tk.END)
        if text != '\n':
            message = text[:-1]
            self.send_message(message)
            self.entry_text.mark_set(tk.INSERT, 1.0)
            self.entry_text.delete(1.0, tk.END)
            self.entry_text.focus_set()

    def send_message(self, message):
        """Only designed for public message"""
        print("Public Chat Window Sent: {}".format(message))
        method = "PUBLIC"
        send_text = make_protocol_msg(method=method, from_who=self.client.username, message=message)
        self.client.send_message(send_text)

    def exit_event(self, event=None):
        method = "LOGOUT"
        send_text = make_protocol_msg(method=method, from_who=self.client.username)
        self.client.send_message(send_text)
        self.client.exit_client()

    def update_login_list(self, active_users):
        active_users = [name for name in str(active_users).split(" ") if name != ""]
        self.login_list.delete(0, tk.END)
        for user in active_users:
            self.login_list.insert(tk.END, user)
        self.login_list.select_set(0)

    def display_message(self, message, is_me=False):
        self.message_window.configure(state='normal')
        if is_me:
            self.message_window.insert(tk.END, message, 'me')
        else:
            self.message_window.insert(tk.END, message)
        self.message_window.configure(state='disabled')
        self.message_window.see(tk.END)

if __name__ == '__main__':
    client = Client(HOST, PORT)
    client.title("Start chatting...")
    client.mainloop()