#!/usr/bin/python3

# Student name and No.: Yashvardhan Nevatia, 3035238797
# Student name and No.: Rohak Singhal, 3035242475
# Development platform: VS Code
# Python version: 3.6.1
# Version: 23


"""
All of the sockets in the readable list have incoming data buffered and available to be read.
All of the sockets in the writable list have free space in their buffer and can be written to.
"""

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
# client = None

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
	def __init__(self, win, _msgqueue, _cmdqueue, do_User, do_List, do_Join, do_Send, do_Poke, do_Quit):
		self.msgqueue = _msgqueue
		self.cmdqueue = _cmdqueue
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
		while self.msgqueue.qsize():
			try:
				msg = self.msgqueue.get(0)
				# print(msg)
				self.MsgWin.insert(1.0, msg)
			except Queue.Empty:
				pass

		while self.cmdqueue.qsize():
			try:
				cmd = self.cmdqueue.get(0)
				# print(msg)
				self.CmdWin.insert(1.0, cmd)
			except Queue.Empty:
				pass

class Client:
	username = ''
	inRoom = False
	roomName = ''
	prev_hash = ''
	members = {}
	sockfd_roomserver = None
	sockud = None
	Exit = False
	msg_queue = Queue.Queue()
	cmd_queue = Queue.Queue()

	Rlist = []
	Wlist = []
	backlist_hash = []
	backlist_dict = {}
	Fowlink = False
	Fowlink_inprogress = False
	P2P_listening = False
	HID = None
	sockfd_forwardlink = None
	sockfd_backwardlink = None

	prev_msgid = 0
	msg_history = {}
	msg_counter = 0
	forward_link_hash = ''

	def __init__(self, port, tkroot):
		self._port = port
		self.tkroot = tkroot

		self.open_backlink()

		self.gui = GUI(self.tkroot, self.msg_queue, self.cmd_queue, self.do_User, self.do_List, self.do_Join,
		self.do_Send, self.do_Poke, self.do_Quit)
		self.periodic_msg_display()

		self.thread_RoomServer()
		self.create_udp()

	""" get info of client """
	def getInfo(self):
		ip, _ = self.sockfd_roomserver.getsockname()
		return ip, self._port

	""" for periodic message display """
	def periodic_msg_display(self):
		self.gui.processIncoming()
		self.tkroot.after(200, self.periodic_msg_display)

	""" waits for Rready """
	def getRready(self):
		# use select to wait for any incoming connection requests or
		# incoming messages or 10 seconds
		try:
			Rready, _, _ = select.select(self.Rlist, [], [], 10)
			return Rready
		except select.error as emsg:
			print("At select, caught an exception:", emsg)
			sys.exit(1)
		except KeyboardInterrupt:
			print("At select, caught the KeyboardInterrupt")
			sys.exit(1)

	""" establish backlink after receiving request """
	def establish_backlink(self, rmsg, newfd):
		values = rmsg.split(':')
		hashval = sdbm_hash(str(values[2])+str(values[3])+str(values[4]))

		if self.quick_verify(hashval) and self.forward_link_hash != hashval:
			msg = "S:{}::\r\n".format(self.prev_msgid)
			newfd.send(msg.encode('ascii'))
			outstr = "\nEstablished backlink with {}".format(values[2])
			self.cmd_queue.put(outstr)
			self.backlist_hash.append(hashval)
			# add the new client connection to READ socket list
			# add the new client connection to WRITE socket list
			self.Rlist.append(newfd)
			self.Wlist.append(newfd)
			peer_ip, peer_port = newfd.getpeername()
			self.backlist_dict[(peer_ip, peer_port)] = hashval
		else:
			print("cancelling this backlink request with {} {} {}".format(values[2], values[3], values[4]))

	""" removes hash value from backlink dict """
	def remove_backlink(self, sd):
		# get ip and port from sd
		peer_ip, peer_port = sd.getpeername()
		# find username of sd
		# peer_username = self.find_peer_username(peer_ip, peer_port)
		# calculate hash
		peer_hashval = self.backlist_dict[(peer_ip, peer_port)]
		# sdbm_hash(str(peer_username)+str(peer_ip)+str(peer_port))
		# remove hash from backlist_hash
		if peer_hashval in self.backlist_hash:
			self.backlist_hash.remove(peer_hashval)
			print('removed {} from backlist hash'.format(peer_hashval))

	""" parses content from received message """
	def get_content(self, msg_text):
		print("msg_text", msg_text)
		msg_content = msg_text[6]
		i = 7
		# last two are left for '' and '\r\n'
		while i < len(msg_text) - 2:
			msg_content += ':'
			msg_content += msg_text[i]
			i += 1
		return msg_content

	""" goes through member list to get username """
	# def find_peer_username(self, peer_ip, peer_port):
	# 	members_list = list(self.members.items())
	# 	peer_username =  next((x[1]._name for x in members_list if x[1]._ip == peer_ip and x[1]._port == peer_port), None)
	# 	return peer_username

	""" listens for all sockets """
	def P2P_listener(self):
		""" start listening on the binded socket """
		self.sockfd_backwardlink.listen(5)
		self.P2P_listening = True
		# add the listening socket to the READ socket list
		self.Rlist.append(self.sockfd_backwardlink)

		while True:
			Rready = self.getRready()
			if not Rready:
				continue
			for sd in Rready:
				if sd == self.sockfd_backwardlink:
					try:
						newfd, caddr = self.sockfd_backwardlink.accept()
					except socket.error as emsg:
						print("Socket accept error: ", emsg)
						continue
					try:
						rmsg = newfd.recv(1024).decode("utf-8")
					except socket.error as emsg:
						print("Socket recv error: ", emsg)
						continue

					if not rmsg:
						print("Connection is broken at sockfd_backwardlink")
						continue
					elif rmsg[0] == "P":
						self.establish_backlink(rmsg, newfd)
					else:
						print("random message", rmsg)
				else:
					try:
						rmsg = sd.recv(1024).decode("utf-8")
					except Exception as emsg:
						print("Socket recv error: ", emsg)
						continue
					if not rmsg:
						print("Connection is broken at sd")
						self.Wlist.remove(sd)
						self.Rlist.remove(sd)
						if sd == self.sockfd_forwardlink:
							self.Fowlink = False
							self.forward_link_hash = ''
							fowlink_thd = threading.Thread(target = self.thread_ForwardLink, daemon=True)
							fowlink_thd.start()
						else:
							self.remove_backlink(sd)
					elif rmsg[0] == "T":
						msg_text = rmsg.split(':')
						msg_room = msg_text[1]
						msg_origin_hid = msg_text[2]
						msg_origin_username = msg_text[3]
						msg_id = msg_text[4]
						msg_length = msg_text[5]
						msg_content = self.get_content(msg_text)

						if self.roomName != msg_room:
							# print("message received from some other room.")
							continue
						elif not self.quick_verify(msg_origin_hid):
							# print("message received from stranger")
							continue
						else:
							if msg_origin_hid in self.msg_history:
								if msg_id in self.msg_history[msg_origin_hid]:
									print("message already received.")
									continue
								else:
									self.msg_history[msg_origin_hid][msg_id] = 1
							else:
								self.msg_history[msg_origin_hid] = {msg_id : 1}

						self.prev_msgid = msg_id

						msg_display = "\n[{}] {}".format(msg_origin_username, msg_content)
						print("putting this in message queue 1", msg_display)
						self.msg_queue.put(msg_display)

						if len(self.Wlist) > 1:
							print("Relay it to others.")
							# relay it to everyone except the original sender and the client that relayed the message
							for p in self.Wlist:
								if p != sd:
									try:
										p.send(rmsg.encode('ascii'))
									except Exception as e:
										print("Socket send error", e)
					else:
						# print("THIS NEVER HAPPENS!!")
						self.Wlist.remove(sd)
						self.Rlist.remove(sd)
						if sd == self.sockfd_forwardlink:
							self.Fowlink = False
							self.forward_link_hash = ''
							fowlink_thd = threading.Thread(target = self.thread_ForwardLink, daemon=True)
							fowlink_thd.start()
						else:
							self.remove_backlink(sd)

	""" goes through given logic to establish forwardlink """
	def establish_forwardlink(self):
		self.Fowlink_inprogress = True
		my_ip, my_port = self.getInfo()
		my_hashval = self.HID
		members_list = list(self.members.items())
		members_list.sort(key = lambda x: x[1]._hashval)
		memlist_size = len(members_list)
		x = [members_list[i][1]._hashval for i in range(memlist_size)].index(my_hashval)
		start = (x+1) % memlist_size

		while start != x:
			#if there is an existing TCP connection between the member at gList[start] and H
			#(i.e., a “backward link”)
			candidate = members_list[start][1]
			if candidate._hashval in self.backlist_hash:
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
							,my_port, self.prev_msgid )
				self.sockfd_forwardlink.send(msg.encode('ascii'))
				try:
					response = self.sockfd_forwardlink.recv(100).decode("utf-8")
					if response[0] == "S":
						outstr = "\nEstablished forwardlink with {}".format(candidate._name)
						self.cmd_queue.put(outstr)
						self.Fowlink = True
						self.Rlist.append(self.sockfd_forwardlink)
						self.Wlist.append(self.sockfd_forwardlink)
						self.forward_link_hash = candidate._hashval
						break
				except Exception as e:
					print("Exception", e)
					start = (start+1) % memlist_size
					continue

		self.Fowlink_inprogress = False

	""" called to start new forward link -> calls connect_Forwardlink """
	def thread_ForwardLink(self):
		# if not already forwardlinked and not already trying to establish a forwardlink
		while not self.Fowlink:
			if not self.Fowlink_inprogress:
				fowlink_thd = threading.Thread(target=self.establish_forwardlink, daemon=True)
				fowlink_thd.start()
			sleep(5)

	""" check if request from valid member """
	def quick_verify(self, hash_verify):
		verified = False
		for member in self.members:
			if str(self.members[member]._hashval) == str(hash_verify):
				return True

		# send join info
		userIP, userPort = self.getInfo()
		msg = "J:{}:{}:{}:{}::\r\n".format(self.roomName, self.username, userIP, str(userPort))
		try:
			self.sockfd_roomserver.send(msg.encode("ascii"))
		except Exception as e:
			print("unable to quick verify:", e)
			return False

		response = self.sockfd_roomserver.recv(1024).decode("utf-8")
		print("reached here inside quick verify")
		if response[0] == "M":
			values = response.split(':')
			# might as well update my own member list
			self.members.clear()
			i = 2
			while i+2 < len(values):
				hash_str = sdbm_hash(str(values[i])+str(values[i+1])+str(values[i+2]))
				self.members[values[i]] = Member(values[i], values[i+1], int(values[i+2]), hash_str)
				if str(hash_str) == str(hash_verify):
					verified = True
				i += 3

		print("returned quick verify {}".format(verified))
		return verified

	""" called only once to start p2p listening """
	def thread_BackwardLink(self):
		if not self.P2P_listening:
			p2p_thd = threading.Thread(target = self.P2P_listener)
			p2p_thd.start()

	""" if hash value changed, update members dict """
	def update_members(self, values):
		i = 2
		self.members.clear()
		print("{} recieved new member list".format(self.username))
		# forwardlink_hash_flag = False
		while i+2 < len(values):
			hash_str = str(values[i])+str(values[i+1])+str(values[i+2])
			hash_val = sdbm_hash(hash_str)
			# if hash_val == self.forward_link_hash:
			# 	forwardlink_hash_flag = True
			self.members[values[i]] = Member(values[i], values[i+1], int(values[i+2]), hash_val)
			i += 3

		# if self.Fowlink and not forwardlink_hash_flag:
		# 	outstr = "\nOld forward link broken. Will try again."
		# 	self.cmd_queue.put(outstr)
		# 	self.Fowlink= False

		if not self.Fowlink:
			# print("starting forward link thread. this statement should only print once.")
			fowlink_thd = threading.Thread(target = self.thread_ForwardLink, daemon=True)
			fowlink_thd.start()

	""" called once in init -> start listening as server """
	def open_backlink(self):
		self.sockfd_backwardlink = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.sockfd_backwardlink.bind(('', self._port))
		except socket.error as emsg:
			print("Socket bind error, exiting: ", emsg)
			sys.exit(0)

	""" listening to the roomserver """
	def roomserver_listener(self):
		while True:
			response = self.sockfd_roomserver.recv(1024).decode("utf-8")

			# response from list
			if response[0] == "G":
				self.cmd_queue.put("\n{}".format(response))

			# response from join
			elif response[0] == "M":
				values = response.split(':')
				if values[1] != self.prev_hash:
					self.prev_hash = values[1]
					self.update_members(values)

				self.thread_BackwardLink()

	""" establish initial connection with room server"""
	def connect_to_RoomServer(self):
		self.sockfd_roomserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sockfd_roomserver.connect(( sys.argv[1], int(sys.argv[2])))

	""" establish connection and start listening to room server """
	def thread_RoomServer(self):
		self.connect_to_RoomServer()
		roomserver_thd = threading.Thread(target = self.roomserver_listener, daemon=True)
		roomserver_thd.start()
		print('sockname', self.sockfd_roomserver.getsockname())
		print("The_connection_with roomserver at", self.sockfd_roomserver.getpeername(),"has_been_established")

	""" send tcp message to room server"""
	def send_tcp(self, msg):
		if self.sockfd_roomserver:
			self.sockfd_roomserver.send(msg.encode("ascii"))

	""" send join request to room server every 20 seconds"""
	def join_and_keep_Alive(self):
		while True:
			userIP, userPort = self.getInfo()
			msg = "J:{}:{}:{}:{}::\r\n".format(self.roomName, self.username, userIP, str(userPort))
			try:
				self.send_tcp(msg)
			except Exception:
				# if the connection hasn't been established
				# try establishing it
				self.connect_to_RoomServer()
				self.send_tcp(msg)
			sleep(20)

	# Functions to handle user input
	""" specify username """
	def do_User(self):
		username = self.gui.userentry.get()
		outstr = ''
		if self.inRoom:
			outstr = "\nAlready in room. Cant change your username."
		elif not username:
			outstr = "\nInvalid Username: Empty Username"
		else:
			self.username = username
			outstr = "\n[User] username: {}".format(username)
		self.gui.CmdWin.insert(1.0, outstr)
		self.gui.userentry.delete(0, END)
		my_ip, my_port = self.getInfo()
		self.HID = sdbm_hash(str(self.username) + str(my_ip) + str(my_port))

	""" return list of rooms """
	def do_List(self):
		# global client
		# self.gui.CmdWin.insert(1.0, "\nPress List")
		msg = "L::\r\n"
		try:
			self.send_tcp(msg)
		except Exception:
			# if the connection hasn't been established
			# try establishing it
			self.connect_to_RoomServer()
			self.send_tcp(msg)

	""" join a room and start keep alive procedure """
	def do_Join(self):
		# global client
		# self.gui.CmdWin.insert(1.0, "\nPress JOIN")
		roomname = self.gui.userentry.get()
		self.gui.userentry.delete(0, END)
		if self.inRoom:
			self.gui.CmdWin.insert(1.0, "\nAlready in a room.")
		elif self.username == '':
			self.gui.CmdWin.insert(1.0, "\nEnter Username.")
		elif roomname == '':
			self.gui.CmdWin.insert(1.0, "\nEnter Room name.")
		else:
			self.roomName = roomname
			self.inRoom = True
			self.gui.CmdWin.insert(1.0, "\nJoined Room.")
			keepalive_thd = threading.Thread(target = self.join_and_keep_Alive, daemon=True)
			keepalive_thd.start()

	""" send message to peer """
	def do_Send(self):
		# self.gui.CmdWin.insert(1.0, "\nPress Send")
		msg_text = self.gui.userentry.get()
		if not self.inRoom or not msg_text: return
		self.gui.userentry.delete(0, END)

		msg_display = "\n[{}] {}".format(self.username, msg_text)
		print("putting this in message queue", msg_display)
		# self.msg_queue.put(msg_display)
		self.gui.MsgWin.insert(1.0, msg_display)

		self.msg_counter += 1
		msg_id = self.msg_counter
		msg = "T:{}:{}:{}:{}:{}:{}::\r\n".format(
			self.roomName, self.HID, self.username, msg_id, len(msg_text), msg_text)
		print("sending this message", msg)
		# try sending message to forwardlink
		try:
			if self.Fowlink:
				self.sockfd_forwardlink.send(msg.encode('ascii'))
				if self.HID in self.msg_history:
					self.msg_history[self.HID][msg_id] = 1
				else:
					self.msg_history[self.HID] = {msg_id : 1}
		# set up forward link if broken / not established
		except Exception as e:
			print("{} unable to send msg to forwardlinks: {}".format(self.username, e))
			self.Fowlink = False

		# try sending to all backlinks
		try:
			for p in self.Wlist:
				if p != self.sockfd_forwardlink:
					p.send(msg.encode('ascii'))
		except Exception as e:
			print("{} unable to send msg to backwardlinks: {}".format(self.username, e))
			# self.thread_BackwardLink()

	""" call close_connection() and quit """
	def do_Quit(self):
		# global client
		# client.Exit = True
		self.gui.CmdWin.insert(1.0, "\nPress Quit")
		self.close_connection()
		sys.exit(0)

	""" do udp poke """
	def do_Poke(self):
		# global client
		self.gui.CmdWin.insert(1.0, "\nPress Poke")
		topoke = self.gui.userentry.get()
		if not self.inRoom:
			self.gui.CmdWin.insert(1.0, "\n Join a room first")
		elif topoke == '':
			for user in self.members:
				if not user == self.username:
					self.gui.CmdWin.insert(1.0, "\n{}".format(user))
			self.gui.CmdWin.insert(1.0, "\nTo whom do you want to send the poke?")
		elif (topoke not in self.members) or topoke == self.username:
			self.gui.CmdWin.insert(1.0, "\nPoke error.")
		else:
			self.poker(topoke)
			self.gui.userentry.delete(0, END)

	""" close all socket threads and connections """
	def close_connection(self):
		# try:

		if self.sockfd_roomserver:
			self.sockfd_roomserver.close()

		if self.Fowlink:
			self.sockfd_forwardlink.close()

		if self.sockfd_backwardlink:
			for connnection in self.Wlist:
				try:
					connnection.close()
				except Exception as e:
						print("Error closing connection: ", e)
						sys.exit(0)
			self.sockfd_backwardlink.close()

	""" create new udp socket for poke everytime do_Poke() """
	def poker(self, topoke):
		# global client
		msg = "K:{}:{}::\r\n".format(self.roomName, self.username)
		topoke_ip = self.members[topoke]._ip
		topoke_port = self.members[topoke]._port
		print("for poking", topoke_ip, topoke_port)
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.sendto(msg.encode("ascii"), (topoke_ip, topoke_port))
		sock.settimeout(2)
		try:
			_, _ = sock.recvfrom(1024)
			self.gui.CmdWin.insert(1.0, "\nPoked and got ACK.")
		except socket.timeout:
			print("Timeout!!! Try again...")
			self.gui.CmdWin.insert(1.0, "\nDid not receive ACK flag.")
		sock.close()

	""" creates udp socket and call udp_listener() """
	def create_udp(self):
		self.sockud = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sockud.bind(('', self._port))
		udpthd = threading.Thread(target=self.udp_listener, daemon=True)
		udpthd.start()

	""" receive pokes from other users """
	def udp_listener(self):
		while True:
			response, addr = self.sockud.recvfrom(1024)
			response = response.decode("utf-8")
			print("received at udp", response)
			if response[0] == 'K':
				msg = "A::\r\n"
				self.sockud.sendto(msg.encode("ascii"), (addr[0], addr[1]))
				msg = "\n{} just poked you".format(response.split(':')[2])
				# print(msg)
				self.msg_queue.put(msg)

def main():
	# global client
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	win = Tk()
	win.title("MyP2PChat")

	# client =
	Client(int(sys.argv[3]), win)

	win.mainloop()

if __name__ == "__main__":
	main()
