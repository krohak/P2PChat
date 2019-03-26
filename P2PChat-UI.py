#!/usr/bin/python3

# Student name and No.: Yashvardhan Nevatia, 3035238797
# Student name and No.: Rohak Singhal, 3035242475
# Development platform: VS Code
# Python version: 3.6.1
# Version: 1


from tkinter import *
import sys
import socket
import threading
# import socket.timeout as TimeoutException
from time import sleep

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
# Global variables
#
client = None

# TODO: get member class ready, add ip and host to it along with username.
# parse the response string and add to member list



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
	sockfd_roomserver = None
	sockud = None
	Exit = False

	def __init__(self, port):
		self._port = port
	
	def getInfo(self):
		ip, _ = self.sockfd_roomserver.getsockname()
		return ip, self._port

	def update_members(self, values):
		i = 2
		self.members.clear()
		print(values)
		while i+2 < len(values):
			self.members[values[i]] = Member(values[i], values[i+1], int(values[i+2]))
			i += 3

	def roomserver_listener(self):
		while True:
			response = self.sockfd_roomserver.recv(1024).decode("utf-8")
			show = True
			if response[0] == "G":
				pass
			elif response[0] == "M":
				values = response.split(':')
				if values[1] != self.prev_hash:
					self.prev_hash = values[1]
					self.update_members(values)
				else:
					show = False
			if show:
				print(response)
				CmdWin.insert(1.0, "\n" + response)

	def udp_listener(self):
		while True:
			response, addr = self.sockud.recvfrom(1024)
			response = response.decode("utf-8")
			print("received at udp", response)
			if response[0] == 'K':
				msg = "A::\r\n"
				self.sockud.sendto(msg.encode("ascii"), (addr[0], addr[1]))
				msg = "{} just poked you".format(response.split(':')[2])
				print(msg)
				CmdWin.insert(1.0, "\n" + msg)

	def create_udp(self):
		self.sockud = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sockud.bind(('', self._port))
		updthd = threading.Thread(target=self.udp_listener, daemon=True)
		updthd.start()

	def connect_to_RoomServer(self):
		self.sockfd_roomserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sockfd_roomserver.connect(( sys.argv[1], int(sys.argv[2])))

	def thread_RoomServer(self):
		self.connect_to_RoomServer()

		roomserver_thd = threading.Thread(target = self.roomserver_listener, daemon=True)
		roomserver_thd.start()
		print('sockname', self.sockfd_roomserver.getsockname())
		print("The_connection_with", self.sockfd_roomserver.getpeername(),"has_been_established")

	def send_tcp(self, msg):
		if self.sockfd_roomserver:
			self.sockfd_roomserver.send(msg.encode("ascii"))

	def close_connection(self):
		self.sockfd_roomserver.close()




#
# Functions to handle user input
#

def do_Quit():
	global client
	# client.Exit = True
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
	try:
		client.send_tcp(msg)
	except Exception: 
		# if the connection hasn't been established
		# try establishing it
		client.connect_to_RoomServer()
		client.send_tcp(msg)

def join_and_keep_Alive():
	global client
	while True:
		userIP, userPort = client.getInfo()
		msg = "J:{}:{}:{}:{}::\r\n".format(client.roomName, client.username, userIP, str(userPort))
		try:
			client.send_tcp(msg)
		except Exception:
			# if the connection hasn't been established
			# try establishing it
			client.connect_to_RoomServer()
			client.send_tcp(msg)
		sleep(20)

def do_Join():
	global client
	CmdWin.insert(1.0, "\nPress JOIN")
	roomname = userentry.get()
	userentry.delete(0, END)
	if client.inRoom:
		CmdWin.insert(1.0, "\nAlready in a room.")
	elif client.username == '':
		CmdWin.insert(1.0, "\nEnter Username.")
	elif roomname == '':
		CmdWin.insert(1.0, "\nEnter Room name.")
	else:
		client.roomName = roomname
		client.inRoom = True
		keepalive_thd = threading.Thread(target = join_and_keep_Alive, daemon=True)
		keepalive_thd.start()


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
		CmdWin.insert(1.0, "\n To whom do you want to send the poke?")
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


def main():
	global client
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	client = Client(int(sys.argv[3]))
	client.thread_RoomServer()
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
