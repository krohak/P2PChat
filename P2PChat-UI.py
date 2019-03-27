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
import queue as Queue
from collections import OrderedDict
import select

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
	def __init__(self, name, ip, port, hashval):
		self._name = name
		self._ip = ip
		self._port = port
		self._hashval = hashval

#
# Set up of Basic UI
#
class GUI:
	def __init__(self, win, queue, do_User, do_List, do_Join, do_Send, do_Poke, do_Quit):
		self.queue = queue
		self.create_frames(win, do_User, do_List, do_Join, do_Send, do_Poke, do_Quit)

	def create_frames(self, win, do_User, do_List, do_Join, do_Send, do_Poke, do_Quit):
		#Top Frame for Message display
		topframe = Frame(win, relief=RAISED, borderwidth=1)
		topframe.pack(fill=BOTH, expand=True)
		topscroll = Scrollbar(topframe)
		MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
		MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
		topscroll.pack(side=RIGHT, fill=Y, expand=True)
		MsgWin.config(yscrollcommand=topscroll.set)
		topscroll.config(command=MsgWin.yview)
		self.MsgWin = MsgWin

		#Top Middle Frame for buttons
		topmidframe = Frame(win, relief=RAISED, borderwidth=1)
		topmidframe.pack(fill=X, expand=True)
		Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
		Butt01.pack(side=LEFT, padx=8, pady=8)
		Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
		Butt02.pack(side=LEFT, padx=8, pady=8)
		Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
		Butt03.pack(side=LEFT, padx=8, pady=8)
		Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
		Butt04.pack(side=LEFT, padx=8, pady=8)
		Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
		Butt06.pack(side=LEFT, padx=8, pady=8)
		Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
		Butt05.pack(side=LEFT, padx=8, pady=8)

		#Lower Middle Frame for User input
		lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
		lowmidframe.pack(fill=X, expand=True)
		userentry = Entry(lowmidframe, fg="blue")
		userentry.pack(fill=X, padx=4, pady=4, expand=True)
		self.userentry = userentry

		#Bottom Frame for displaying action info
		bottframe = Frame(win, relief=RAISED, borderwidth=1)
		bottframe.pack(fill=BOTH, expand=True)
		bottscroll = Scrollbar(bottframe)
		CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
		CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
		bottscroll.pack(side=RIGHT, fill=Y, expand=True)
		CmdWin.config(yscrollcommand=bottscroll.set)
		bottscroll.config(command=CmdWin.yview)
		self.CmdWin = CmdWin

	def processIncoming(self):
		while self.queue.qsize():
			try:
				msg = self.queue.get(0)
				print(msg)
				self.CmdWin.insert(1.0, "\n" + msg)
			except Queue.Empty:
				pass

class Client:
	username = ''
	inRoom = False
	roomName = ''
	prev_hash = ''
	members = {}
	sockfd_roomserver = None
	sockfd_forwardlink = None
	sockfd_backwardlink = None
	sockud = None
	Exit = False
	msg_queue = Queue.Queue()
	Rlist = []
	Wlist = []
	Backlist_hash = []
	Fowlink = False
	P2P_listening = False

	def __init__(self, port, tkroot):
		self._port = port
		self.gui = GUI(tkroot, self.msg_queue, self.do_User, self.do_List, self.do_Join, 
		self.do_Send, self.do_Poke, self.do_Quit)
		self.tkroot = tkroot
		self.periodic_msg_display()
	
	def getInfo(self):
		ip, _ = self.sockfd_roomserver.getsockname()
		return ip, self._port
	
	def periodic_msg_display(self):
		self.gui.processIncoming()
		self.tkroot.after(200, self.periodic_msg_display)

	def check_Backlink(self, member_hash):
		# do something
		if member_hash in self.Backlist_hash:
			return True
		return False
	
	def P2P_listener(self):
		# open backlink socket
		self.sockfd_backwardlink = socket.socket()
		try:
			self.sockfd_backwardlink.bind(('', self._port))
		except socket.error as emsg:
			print("Socket bind error: ", emsg)
			return 

		self.sockfd_backwardlink.listen(5)
		self.P2P_listening = True

		# add the listening socket to the READ socket list
		self.Rlist.append(self.sockfd_backwardlink)

		# create an empty WRITE socket list
		# Wlist = []

		while True:
			# use select to wait for any incoming connection requests or
			# incoming messages or 10 seconds
			try:
				Rready, Wready, Eready = select.select(self.Rlist, [], [], 10)
			except select.error as emsg:
				print("At select, caught an exception:", emsg)
				sys.exit(1)
			except KeyboardInterrupt:
				print("At select, caught the KeyboardInterrupt")
				sys.exit(1)

		
		# if has incoming activities
		if Rready:
			for sd in Rready:
				if sd == self.sockfd_backwardlink:
					try:
						newfd, caddr = self.sockfd_backwardlink.accept()
						print("A new client has arrived. It is at:", caddr)
					
					# handle error
					except socket.error as emsg:
					  print("Socket accept error: ", emsg)
					  continue
					try:
						rmsg = newfd.recv(1024).decode("utf-8")                 
					except socket.error as emsg:
					    print("Socket recv error: ", emsg)
					    continue

					if rmsg == b'':
					    print("Connection is broken")
					    continue

					# p2p handshake 
					if rmsg[0] == "P":
						print("P", rmsg)
						msg = "S:{}::\r\n".format(2)
						newfd.send(msg.encode('ascii'))
					
					else:
						print("here", rsmg)

					self.Rlist.append(newfd)
					self.Wlist.append(newfd)

                # elif sd == self.sockfd_forwardlink:
                #     # do something
                #     pass
				
				else:
					rmsg = sd.recv(1024).decode("utf-8")
					# regular text message
					if rmsg[0] == "T":
						print("T", rmsg)
						print("Got a message!!")
						if len(self.Wlist) > 1:
							print("Relay it to others.")
							# relay it to everyone except the sender
							for p in self.Wlist:
								if p != sd:
									p.send(rmsg)
					else:
						print("A client connection is broken!!")
						self.Wlist.remove(sd)
						self.Rlist.remove(sd)
		else:
			print("Idling")	

	def connect_Forwardlink(self):
		my_ip, my_port = self.getInfo()
		my_hashval = sdbm_hash(str(self.username) + str(my_ip) + str(my_port))

		members_dict = OrderedDict(self.members)
		members_dict = OrderedDict(sorted(members_dict.items(), key=lambda x: x[1]._hashval))
		members_list = list(members_dict.items())
		memlist_size = len(members_list)
		x = [members_list[i][1]._hashval for i in range(memlist_size)].index(my_hashval)
		start = (x+1) % memlist_size
		
		while start != x:
			#if there is an existing TCP connection between the member at gList[start] and H
			#(i.e., a “backward link”)
			candidate = members_list[start][1]
			if self.check_Backlink(candidate._hashval):
				start = (start+1) % memlist_size
			else:
				try:
					# establish a TCP connection to the member at gList[start] 
					self.sockfd_forwardlink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					self.sockfd_forwardlink.connect(( candidate._ip, candidate._port ))
				except Exception as e:
					print("Exception", e)
					start = (start+1) % memlist_size
					continue

				# p2p handshake
				msg = "P:{}:{}:{}:{}:{}::\r\n".format(self.roomName, self.username, my_ip
							,my_port, 1 )
				# send message
				self.sockfd_forwardlink.send(msg.encode('ascii'))
				# recv response
				response = self.sockfd_forwardlink.recv(100).decode("utf-8") 
				if response[0] == "S":
					self.Fowlink = True
					self.Rlist.append(self.sockfd_forwardlink)
					self.Wlist.append(self.sockfd_forwardlink)
					break
				else:
					start = (start+1) % memlist_size
					continue


	def update_members(self, values):
		i = 2
		self.members.clear()
		print(values)
		while i+2 < len(values):
			hash_str = str(values[i])+str(values[i+1])+str(values[i+2])
			self.members[values[i]] = Member(values[i], values[i+1], int(values[i+2]), sdbm_hash(hash_str))
			i += 3

		# periodically try connecting to forward link
		if not self.Fowlink:
			print("fowlink")
			fowlink_thd = threading.Thread(target=self.connect_Forwardlink, daemon=True)
			fowlink_thd.start()
			# self.connect_Forwardlink()
		
		if not self.P2P_listening:
			print("p2plistening")
			p2p_thd = threading.Thread(target = self.P2P_listener, daemon=True)
			p2p_thd.start()

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
				self.msg_queue.put(response)
				# self.gui.CmdWin.insert(1.0, "\n" + response)

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
				self.msg_queue.put(msg)
				# self.gui.CmdWin.insert(1.0, "\n" + msg)

	def create_udp(self):
		self.sockud = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sockud.bind(('', self._port))
		udpthd = threading.Thread(target=self.udp_listener, daemon=True)
		udpthd.start()

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

	# Functions to handle user input
	def do_Quit(self):
		global client
		# client.Exit = True
		client.close_connection()
		self.gui.CmdWin.insert(1.0, "\nPress Quit")
		sys.exit(0)

	def do_User(self):
		global client
		username = self.gui.userentry.get()
		outstr = ''
		if client.inRoom:
			outstr = "\nAlready in room. Cant change your username."
		elif not username:
			outstr = "\nInvalid Username: Empty Username"
		else:
			client.username = username
			outstr = "\n[User] username: {}".format(username)
		self.gui.CmdWin.insert(1.0, outstr)
		self.gui.userentry.delete(0, END)

	def do_List(self):
		global client
		self.gui.CmdWin.insert(1.0, "\nPress List")
		msg = "L::\r\n"
		try:
			client.send_tcp(msg)
		except Exception: 
			# if the connection hasn't been established
			# try establishing it
			client.connect_to_RoomServer()
			client.send_tcp(msg)

	def join_and_keep_Alive(self):
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

	def do_Join(self):
		global client
		self.gui.CmdWin.insert(1.0, "\nPress JOIN")
		roomname = self.gui.userentry.get()
		self.gui.userentry.delete(0, END)
		if client.inRoom:
			self.gui.CmdWin.insert(1.0, "\nAlready in a room.")
		elif client.username == '':
			self.gui.CmdWin.insert(1.0, "\nEnter Username.")
		elif roomname == '':
			self.gui.CmdWin.insert(1.0, "\nEnter Room name.")
		else:
			client.roomName = roomname
			client.inRoom = True
			keepalive_thd = threading.Thread(target = self.join_and_keep_Alive, daemon=True)
			keepalive_thd.start()

	def do_Send(self):
		self.gui.CmdWin.insert(1.0, "\nPress Send")

	def do_Poke(self):
		global client
		self.gui.CmdWin.insert(1.0, "\nPress Poke")
		topoke = self.gui.userentry.get()
		if not client.inRoom:
			self.gui.CmdWin.insert(1.0, "\n Join a room first")
		elif topoke == '':
			for user in client.members:
				if not user == client.username:
					self.gui.CmdWin.insert(1.0, "\n{}".format(user))
			self.gui.CmdWin.insert(1.0, "\n To whom do you want to send the poke?")
		elif (topoke not in client.members) or topoke == client.username:
			self.gui.CmdWin.insert(1.0, "\nPoke error.")
		else:
			self.poker(topoke)
			self.gui.userentry.delete(0, END)

	def poker(self, topoke):
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
			self.gui.CmdWin.insert(1.0, "\nPoked and got ACK.")
		except socket.timeout:
			print("Timeout!!! Try again...")
			self.gui.CmdWin.insert(1.0, "\nDid not receive ACK flag.")
		sock.close()


def main():
	global client
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	
	win = Tk()
	win.title("MyP2PChat")
	
	client = Client(int(sys.argv[3]), win)
	client.thread_RoomServer()
	client.create_udp()

	win.mainloop()

if __name__ == "__main__":
	main()
