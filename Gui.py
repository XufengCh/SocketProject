# encding='utf-8'
import tkinter as tk
import threading
from MySocketPro import *
from tkinter import messagebox
from tkinter import scrolledtext

class GUI(threading.Thread):
    def __init__(self, client):
        super().__init__(daemon=False, target=self.run)
        self.font = ('consolas', 13)
        self.client = client
        self.login_window = None
        self.main_window = None
        # key: username value: ChatWindow
        self.private_window = {}
        # key: username value=color
        self.user_font = {}

        self.lock = threading.RLock()

    def run(self):
        self.login_window = LoginWindow(self, ('consolas', 12))
        self.main_window = ChatWindow(self, 'Chatroom --- ' + self.login_window.login, self.font, False)
        self.main_window.run()

    @staticmethod
    def display_alert(message):
        """Display alert box"""
        messagebox.showinfo('Error', message)

    def update_login_list(self, active_users):
        self.main_window.update_login_list(active_users)
        with self.lock:
            for user in active_users:
                if user not in self.user_font:
                    self.user_font[user] = "#000000"

            for user in self.private_window:
                if user not in active_users:
                    self.display_alert("{} has logged out!".format(user))
                    self.private_window[user].exit()
                    del self.private_window[user]

    def display_message(self, data, is_public, senter, private_chatter=None):
        if senter not in self.user_font:
            return
        if is_public:
            self.main_window.display_message(data)
        else:
            if private_chater != None and private_chater != '' and private_chater not in self.private_window:
                self.start_private_window(private_chatter)

            self.private_window[private_chatter].display_message(data)

    def start_private_window(self, private_chater):
        with self.lock:
            # create private window
            private_window = ChatWindow(title="Private Chat With: {}".format(private_chatter), gui=self,
                                        font=self.font, is_private=True, receiver_name=private_chatter)
            self.private_window[private_chatter] = private_window
            private_window.run()



class Window():
    def __init__(self, title, font):
        self.root = tk.Tk()
        self.title = title
        self.root.title(title)
        self.font = font

class LoginWindow(Window):
    def __init__(self, gui, font):
        super().__init__("Start Chatting", font)
        self.gui = gui
        self.label0 = None
        self.label1 = None
        self.frame0 = None
        self.frame1 = None
        self.frame2 = None
        self.entry = None
        self.button = None
        self.login = None

        self.build_window()
        self.run()

    def build_window(self):
        """Build Login Window"""
        # window size
        self.root.geometry('300x100')

        # frame0
        self.frame0 = tk.Frame(self.root)
        self.label0 = tk.Label(self.frame0, text="Welcome to Tony's Chatroom",
                               font=("consolas", 12))
        self.label0.pack()
        self.frame0.pack(side=tk.TOP)

        # frame1
        self.frame1 = tk.Frame(self.root)

        self.label1 = tk.Label(self.frame1, text="Your Name: ", font=self.font)
        self.label1.pack(side=tk.LEFT)

        self.entry = tk.Entry(self.frame1, width=15, font=self.font)
        self.entry.pack(side=tk.RIGHT, expand=tk.YES)
        self.entry.bind('<Return>', self.get_login_event)

        self.frame1.pack(padx=5, pady=5)

        # frame2
        self.frame2 = tk.Frame(self.root)

        self.button = tk.Button(self.frame2, text="Login", width=15, font=self.font)
        self.button.pack(side=tk.RIGHT)
        self.button.bind('<Button-1>', self.get_login_event)

        self.frame2.pack(padx=5, pady=4)

    def run(self):
        self.root.mainloop()
        self.root.destroy()

    def get_login_event(self, event=None):
        """Get login from login box and close login window"""
        self.login = self.entry.get()
        if self.login == None or self.login == '' or self.login.find(' ') != -1:
            return
        with self.gui.client.lock:
            self.gui.client.username = self.login
            self.gui.client.notify_server(self.login, "LOGIN")

class ChatWindow(Window):
    def __init__(self, title, gui, font, is_private, receiver_name=None):
        super().__init__(title, font)
        self.gui = gui
        self.is_private = is_private
        if self.is_private:
            self.receiver = receiver_name

        self.message_window = None
        self.login_list = None
        self.entry_text = None
        self.send_button = None
        self.exit_button = None
        self.lock = threading.RLock()
        # username
        #self.login = self.gui.login_window.login
        self.login = None

        self.build_window()
        #self.run()

    def build_window(self):
        """Build chat window"""
        # window size
        self.root.geometry('750x450')
        self.root.resizable(0, 0)

        main_frame = tk.Frame(self.root)

        # Listbox widget for displaying active users and selecting them
        self.login_list = tk.Listbox(main_frame, width=15, height=20, selectmode=tk.SINGLE, font=self.font,
                                    selectbackground='#DCDCDC')
        self.login_list.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="nsew")
        self.login_list.bind("<Double-Button-1>", self.start_private_chat)

        # ScrolledText widget for displaying messages
        self.message_window = scrolledtext.ScrolledText(main_frame, wrap='word', font=self.font,
                                                        width=60, height=15, undo=True)
        self.message_window.insert(tk.END, 'Start Chatting !\n\n')
        self.message_window.configure(state='disabled')
        self.message_window.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="nsew")

        # Entry widget for typing messages in
        self.entry_text = tk.Text(main_frame, width=45, height=5, undo=True, font=self.font)
        self.entry_text.focus_set()
        self.entry_text.bind('<Return>', self.send_entry_event)
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

        # Protocol for closing window using 'x' button
        self.root.protocol("WM_DELETE_WINDOW", self.exit_event)

    def run(self):
        self.root.mainloop()
        self.root.destroy()

    def send_message(self, message):
        print("ChatWindow Sent: {}".format(message))
        if self.is_private:
            method = "PRIVATE"
        else:
            method = "PUBLIC"

        sent_text = make_protocol_msg(method=method, from_who=self.login, agent="client.py", message=message)
        self.gui.client.send(sent_text)

    def send_entry_event(self, event=None):
        with self.lock:
            text = self.entry_text.get(1.0, tk.END)
            if text != '\n':
                message = text[:-1]
                self.send_message(message)
                self.entry_text.mark_set(tk.INSERT, 1.0)
                self.entry_text.delete(1.0, tk.END)
                self.entry_text.focus_set()
            else:
                messagebox.showinfo('Warning', 'You must enter non-empty message')

    def exit_event(self, event=None):
        if not self.is_private:
            # exit public chatroom: logout
            self.gui.client.notify_server(self.login, "LOGOUT")
            self.root.quit()
        else:
            # exit private chatroom
            del self.gui.private_window[self.receiver]
            self.root.quit()
            return

    def start_private_chat(self, event=None):
        if self.is_private:
            return
        reciever_name = self.login_list.get(self.login_list.curselection())
        if reciever_name in self.gui.private_window:
            return
        if reciever_name == self.login:
            return
        # create private window
        with self.lock:
            self.gui.start_private_window(reciever_name)

    def update_login_list(self, active_users):
        """Only for public chatroom"""
        with self.lock:
            self.login_list.delete(0, tk.END)
            for user in active_users:
                self.login_list.insert(tk.END, user)
            self.login_list.select_set(0)

    def display_message(self, message):
        with self.lock:
            self.message_window.configure(state='normal')
            self.message_window.insert(tk.END, message)
            self.message_window.configure(state='disabled')
            self.message_window.see(tk.END)


#guiLogin = LoginWindow(None, ("consolas", 12))
#gui = ChatWindow("Chatroom", None, ('consolas', 12), False)