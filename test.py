from collections import OrderedDict

def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff



class Member:
	def __init__(self, name, ip, port, hashval):
		self._name = name
		self._ip = ip
		self._port = port
		self._hashval = hashval



members = {}


name1 = 'rohak'
ip1 = '127.1.1.100'
port1 = 32345
hashval1 = sdbm_hash(str(name1)+str(ip1)+str(port1))
members[name1] = Member(name1, ip1, port1, hashval1)

name1 = 'yash'
ip1 = '127.1.2.100'
port1 = 32346
hashval1 = sdbm_hash(str(name1)+str(ip1)+str(port1))
members[name1] = Member(name1, ip1, port1, hashval1)


members_dict = OrderedDict(members)

members_dict = OrderedDict(sorted(members_dict.items(), key=lambda x: x[1]._hashval))

for member_name, member in members_dict.items():
    print(member_name, member._hashval)

members_list = list(members_dict.items())


x = [members_list[x][1]._hashval for x in range(len(members_list))].index(hashval1)


print(x, hashval1)



start = x+1




# print(members_list[x][1])
# print(members_list[x][1]._hashval)