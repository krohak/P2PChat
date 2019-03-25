#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket

#
# Global variables
#

sockfd = ''
username = ''
myip = ''
inRoom = False
prev_hash = ''
members = {} # List[Member]

# TODO: get member class ready, add ip and host to it along with username.
# parse the response string and add to member list


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
import threading


def do_User():
	if not inRoom:
		global username
		outstr = "\n[User] username: "+userentry.get()
		username = userentry.get()
		CmdWin.insert(1.0, outstr)
		userentry.delete(0, END)
	else:
		CmdWin.insert(1.0, "\nAlready in room ")

def do_List():
	CmdWin.insert(1.0, "\nPress List")
	msg = "L::\r\n"
	# print(msg)
	sockfd.send(msg.encode("ascii"))
	response = sockfd.recv(1024)
	if response.decode("utf-8")[0] != 'G':
		CmdWin.insert(1.0, "\n" + response.decode("utf-8"))
	else:
		sockfd.send(msg.encode("ascii"))
		response = sockfd.recv(1024)
		CmdWin.insert(1.0, "\n" + response.decode("utf-8"))

def update_members(values):
	i = 2
	members.clear()
	print(values)
	while i+2 < len(values):
		members[values[i]] = Member(values[i], values[i+1], values[i+2])
		i += 3
	# print(members)

def join_room():
	global prev_hash
	userIP, userPort = sockfd.getsockname()
	msg = "J:room1:{}:{}:{}::\r\n".format(username, userIP, str(userPort))
	sockfd.send(msg.encode("ascii"))
	response = sockfd.recv(1024)
	response = response.decode("utf-8")
	if  response[0] == "M":
		values = response.split(':')
		if values[1] != prev_hash:
			prev_hash = values[1]
			update_members(values)

def startTimer():
    threading.Timer(20, startTimer).start()
    join_room()

def do_Join():
	global inRoom
	global username
	roomname = userentry.get()
	if username == '':
		CmdWin.insert(1.0, "\nEnter Username")
	elif roomname == '':
		CmdWin.insert(1.0, "\nEnter Room name")
	else:
		CmdWin.insert(1.0, "\nPress JOIN")
		userIP, userPort = sockfd.getsockname()
		roomname = userentry.get()
		msg = "J:{}:{}:{}:{}::\r\n".format(roomname,username, userIP, str(userPort))
		userentry.delete(0, END)
		sockfd.send(msg.encode("ascii"))
		response = sockfd.recv(1024)
		# print(response.decode("utf-8"))
		CmdWin.insert(1.0, "\n" + response.decode("utf-8"))
		inRoom = True
		startTimer()


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
	CmdWin.insert(1.0, "\nPress Quit")
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
	global sockfd
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sockfd.bind(('', int(sys.argv[3])))
	print('sockname', sockfd.getsockname())
	# print('hostname', sockfd.gethostname())
	sockfd.connect( ("localhost", 8000) )
	print("The_connection_with", sockfd.getpeername(), \
	"has_been_established")
	sockfd.recvfrom()
	win.mainloop()

if __name__ == "__main__":
	main()