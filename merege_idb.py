#!/usr/bin/python

import idc
import idaapi
import pickle

user = "user_1"
friend = "user_2"

def create_db(f):

	#
	## function dump
	#
	l = []
	for function in Functions(0, 0xffffffff):

		d = {}
		d["addr"] = function
		d["name"] = GetFunctionName(function)
		d["type"] = GetType(function)
		d["comment"] = GetFunctionCmt(function, True)

		l += [d]

	pickle.dump(l, f)
	print "dumped all function"

	#
	## comment dump
	#
	l = []
	for addr in xrange(MinEA(), MaxEA()):
		d = {}
		comment = GetCommentEx(addr, True)
		if comment:

			d["addr"] = addr
			d["comment"] = comment

			l += [d]

	pickle.dump(l, f)
	print "dumped all comment"

def update_db(f):

	#
	## function update
	#
	function_list = pickle.load(f)

	for function_db in function_list:

		f_name = GetFunctionName(function_db["addr"])
		if f_name != function_db["name"] and function_db["name"] != "sub_":

			MakeNameEx(function_db["addr"], function_db["name"], SN_NON_PUBLIC)
			SetType(function_db["addr"], function_db["type"])

		if function_db["comment"] != GetFunctionCmt(function_db["addr"], True):

			if GetFunctionCmt(function_db["addr"], True) == None:
				comm = function_db["comment"]
			else:
				comm = function_db["comment"] + GetFunctionCmt(function_db["addr"], True)

			SetFunctionCmt(function_db["addr"], comm, True)

	#
	## commment update
	#
	comment_list = pickle.load(f)

	for comment in comment_list:

		if comment["comment"] != GetCommentEx(comment["addr"], True):

			if GetCommentEx(comment["addr"], True) == None:
				comm = comment["comment"]
			else:
				comm = GetCommentEx(comment["addr"], True) + "\n\n" + comment["comment"]
			
			MakeComm(comment["addr"], comm)

	print "update success"

if __name__ == '__main__':

    with open("%s_db_dump.p" % user, "wb") as f:
    	create_db(f)
    
    
    try:
    	f = open("%s_db_dump.p" % friend, "rb")
    	update_db(f)
    	
    except IOError:
    	print "where is the file!?"

    
