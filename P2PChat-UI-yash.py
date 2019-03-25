#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import threading
# import socket.timeout as TimeoutException
from time import sleep
#
# Global variables
#

sockfd = ''
sockud = ''
username = ''
myip = ''
inRoom = False
roomName = ''
prev_hash = ''
members = {} # dict[Member]
updthd = ''
Exit = False
timer = ''
poked = False
# TODO: get member class ready, add ip and host to it along with username.
# parse the response string and add to member list

client = None

class Member:
	def __init__(self, name, ip, port):
		self._name = name
		self._ip = ip
		self._port = port

class Client:
	username = ''
	inRoom = False
	roomName = ''
	prev_hash = ''
	members = {}
	sockfd = None
	sockud = None
	Exit = False

	def __init__(self, ip, port):
		self._ip = ip
		self._port = port

	def update_members(self, values):
		i = 2
		self.members.clear()
		print(values)
		while i+2 < len(values):
			self.members[values[i]] = Member(values[i], values[i+1], int(values[i+2]))
			i += 3

	def tcp_listener(self):
		while True:
			if self.Exit:
				break
			response = self.sockfd.recv(1024).decode("utf-8")
			show = True
			if response[0] == "M":
				values = response.split(':')
				if values[1] != self.prev_hash:
					self.prev_hash = values[1]
					self.update_members(values)
				else:
					show = False
			if show:
				CmdWin.insert(1.0, "\n" + response)

	def udp_listener(self):
		while True:
			if self.Exit:
				break
			response, addr = self.sockud.recvfrom(1024)
			response = response.decode("utf-8")
			print("received at udp", response)
			if response[0] == 'K':
				msg = "A::\r\n"
				self.sockud.sendto(msg.encode("ascii"), (addr[0], addr[1]))
				msg = "{} just poked you".format(response.split(':')[2])
				CmdWin.insert(1.0, "\n" + msg)

	def create_udp(self):
		self.sockud = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sockud.bind(('', int(sys.argv[3])))
		updthd = threading.Thread(target=self.udp_listener, daemon=True)
		updthd.start()

	def create_tcp_with_server(self):
		self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sockfd.bind((self._ip, self._port))
		self.sockfd.connect(( "localhost", int(sys.argv[2])))
		tcpthd = threading.Thread(target = self.tcp_listener, daemon=True)
		tcpthd.start()
		print('sockname', self.sockfd.getsockname())
		print("The_connection_with", self.sockfd.getpeername(), \
		"has_been_established")

	def send_tcp(self, msg):
		if self.sockfd:
			self.sockfd.send(msg.encode("ascii"))

	def close_connection(self):
		self.sockfd.close()


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form a string that be the input
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#
# def startTimer():
# 	global timer
# 	timer = threading.Timer(20, startTimer)
# 	timer.start()
# 	join_room()

def do_Quit():
	global client
	client.Exit = True
	client.close_connection()
	CmdWin.insert(1.0, "\nPress Quit")
	sys.exit(0)

def do_User():
	global client
	username = userentry.get()
	outstr = ''
	if client.inRoom:
		outstr = "\nAlready in room. Cant change your username."
	elif not username:
		outstr = "\nInvalid Username: Empty Username"
	else:
		client.username = username
		outstr = "\n[User] username: {}".format(username)
	CmdWin.insert(1.0, outstr)
	userentry.delete(0, END)

def do_List():
	global client
	CmdWin.insert(1.0, "\nPress List")
	msg = "L::\r\n"
	client.sockfd.send(msg.encode("ascii"))

def join_room():
	global client
	while not client.Exit:
		sleep(20)
		if client.Exit:
			break
		userIP, userPort = client.sockfd.getsockname()
		msg = "J:{}:{}:{}:{}::\r\n".format(client.roomName, client.username, userIP, str(userPort))
		client.send_tcp(msg)

def do_Join():
	global client
	CmdWin.insert(1.0, "\nPress JOIN")
	roomname = userentry.get()
	if client.inRoom:
		CmdWin.insert(1.0, "\nAlready in a room.")
	elif client.username == '':
		CmdWin.insert(1.0, "\nEnter Username.")
	elif roomname == '':
		CmdWin.insert(1.0, "\nEnter Room name.")
	else:
		userIP, userPort = client.sockfd.getsockname()
		client.roomName = roomname
		client.inRoom = True
		msg = "J:{}:{}:{}:{}::\r\n".format(client.roomName, client.username, userIP, str(userPort))
		userentry.delete(0, END)
		client.send_tcp(msg)
		joinerthd = threading.Thread(target = join_room, daemon=True)
		joinerthd.start()
		# startTimer()
		# timer = threading.Timer(20, join_room)

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")

def do_Poke():
	global client
	CmdWin.insert(1.0, "\nPress Poke")
	topoke = userentry.get()
	if not client.inRoom:
		CmdWin.insert(1.0, "\n Join a room first")
	elif topoke == '':
		for i in client.members:
			CmdWin.insert(1.0, "\n{}".format(i))
	elif (topoke not in client.members) or topoke == client.username:
		CmdWin.insert(1.0, "\nPoke error.")
	else:
		poker(topoke)
		userentry.delete(0, END)

def poker(topoke):
	global client
	msg = "K:{}:{}::\r\n".format(client.roomName, client.username)
	topoke_ip = client.members[topoke]._ip
	topoke_port = client.members[topoke]._port
	print(topoke_ip, topoke_port)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto(msg.encode("ascii"), (topoke_ip, topoke_port))
	sock.settimeout(2)
	try:
		message, address = sock.recvfrom(1024)
		CmdWin.insert(1.0, "\nPoked and got ACK.")
	except socket.timeout:
		print("Timeout!!! Try again...")
		CmdWin.insert(1.0, "\nDid not receive ACK flag.")
	sock.close()

# def udp_listener():
# 	global poked
# 	print("entered in this thread function which is running loop")
# 	while True:
# 		if Exit:
# 			break
# 		response, addr = sockud.recvfrom(1024)
# 		response = response.decode("utf-8")
# 		print("received at udp", response)
# 		if response[0] == 'K':
# 			msg = "A::\r\n"
# 			sockud.sendto(msg.encode("ascii"), (addr[0], addr[1]))
# 			msg = "{} just poked you".format(response.split(':')[1])
# 			CmdWin.insert(1.0, "\n" + msg)


# def create_udp():
# 	sockud = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 	sockud.bind(('', int(sys.argv[3])))
# 	updthd = threading.Thread(target=udp_listener, daemon=True)
# 	updthd.start()

def main():
	global client
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	client = Client('', int(sys.argv[3]))
	client.create_tcp_with_server()
	client.create_udp()
	win.mainloop()

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)



if __name__ == "__main__":
	main()
