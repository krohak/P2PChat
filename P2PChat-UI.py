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
import time

#
# Global variables
#

sockfd_roomserver = ''
sockfd_chatroom = ''
username = ''
myip = ''
inRoom = False
RoomName = ''
prev_hash = ''
members = {} # List[Member]
Exit = False

# TODO: get member class ready, add ip and host to it along with username.
# parse the response string and add to member list
# TODO: Make 1 chatroom server socket and 1 chatroom client socket

class Member:
	def __init__(self, name, ip, port):
		self._name = name
		self._ip = ip
		self._port = port


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

def connect_RoomServer():
	global sockfd_roomserver
	sockfd_roomserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sockfd_roomserver.connect( (sys.argv[1], int(sys.argv[2])) )
	print("The_connection_with", sockfd_roomserver.getpeername(), "has_been_established")


def do_User():
	if not inRoom:
		global username
		outstr = "\n[User] username: "+userentry.get()
		username = userentry.get()
		print('username: ', username)
		if not username:
			outstr = "\nInvalid Username: Empty Username"
		CmdWin.insert(1.0, outstr)
		userentry.delete(0, END)
	else:
		CmdWin.insert(1.0, "\nAlready in room ")
		userentry.delete(0, END)

def do_List():
	CmdWin.insert(1.0, "\nPress List")
	msg = "L::\r\n"
	# print(msg)
	try:
		sockfd_roomserver.send(msg.encode("ascii"))
		response = sockfd_roomserver.recv(1024)
	except Exception: 
		# if the connection hasn't been established
		# try establishing it
		connect_RoomServer()
		sockfd_roomserver.send(msg.encode("ascii"))
		response = sockfd_roomserver.recv(1024)
	if response.decode("utf-8")[0] != 'G':
		CmdWin.insert(1.0, "\nError: " + response.decode("utf-8"))
	else:
		# sockfd_roomserver.send(msg.encode("ascii"))
		# response = sockfd_roomserver.recv(1024)
		CmdWin.insert(1.0, "\n" + response.decode("utf-8"))

def update_members(values):
	global members
	i = 2
	members.clear()
	print(values)
	while i+2 < len(values):
		members[values[i]] = Member(values[i], values[i+1], values[i+2])
		i += 3


def keep_Alive():
	global prev_hash
	global RoomName
	global username
	global Exit
	
	while not Exit:
		print('sleeping')
		time.sleep(20)
		if Exit: 
			break
		print('awake')
		userIP, userPort = sockfd_roomserver.getsockname()
		msg = "J:{}:{}:{}:{}::\r\n".format(RoomName, username, userIP, str(userPort))
		sockfd_roomserver.send(msg.encode("ascii"))
		response = sockfd_roomserver.recv(1024)
		response = response.decode("utf-8")
		print(response)
		if response[0] == "M":
			values = response.split(':')
			if values[1] != prev_hash:
				prev_hash = values[1]
				update_members(values)

def do_Join():
	global inRoom
	global username
	global RoomName

	if not inRoom:
		RoomName = userentry.get()
		if username == '':
			CmdWin.insert(1.0, "\nEnter Username")
		elif RoomName == '':
			CmdWin.insert(1.0, "\nEnter Room name")
		else:
			CmdWin.insert(1.0, "\nPress JOIN")
			userIP, userPort = sockfd_roomserver.getsockname()
			RoomName = userentry.get()
			msg = "J:{}:{}:{}:{}::\r\n".format(RoomName,username, userIP, str(userPort))
			userentry.delete(0, END)

			try:
				sockfd_roomserver.send(msg.encode("ascii"))
				response = sockfd_roomserver.recv(1024)
			except Exception:
				# if the connection hasn't been established
				# try establishing it
				connect_RoomServer()
				sockfd_roomserver.send(msg.encode("ascii"))
				response = sockfd_roomserver.recv(1024)	

			CmdWin.insert(1.0, "\n" + response.decode("utf-8"))
			inRoom = True
			# create thread with keep_Alive
			thd_joinroom = threading.Thread(target=keep_Alive, daemon=True) 
			# start new thread
			thd_joinroom.start()

	else:
		CmdWin.insert(1.0, "\nError: Room already joined")		



def do_Send():
	CmdWin.insert(1.0, "\nPress Send")

def do_Poke():
    # CmdWin.insert(1.0, "\nPress Poke")
    topoke = userentry.get()
    if not inRoom:
        CmdWin.insert(1.0, "\n Join a room first")
    elif topoke == '':
        for i in members:
            CmdWin.insert(1.0, "\n{}".format(i))
    elif (topoke not in members) or topoke == username:
       CmdWin.insert(1.0, "\n Poke error.")
    else:
        pass




def do_Quit():
	global Exit
	CmdWin.insert(1.0, "\nPress Quit")
	Exit = True
	sys.exit(0)
	

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

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	global sockfd_roomserver
	global sockfd_chatroom
	
	connect_RoomServer()

	sockfd_chatroom = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sockfd_chatroom.bind(('', int(sys.argv[3])))
	print('Chatroom sockname', sockfd_chatroom.getsockname())
	# print('hostname', sockfd_chatroom.gethostname())

	# sockfd.recvfrom(1024) #UDP recv

	win.mainloop()

if __name__ == "__main__":
	main()