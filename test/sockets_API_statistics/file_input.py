#Licence: GNU/GPL
#Authors: 
#Tao Wan<twan@cc.hut.fi>


#!/usr/bin/python
import sys, re
import shlex
from string_token import *




def readFile(file):

	string_temp = ""

	fd = open(file)

	#This is just an example about how to do regular express 
	#for line in sys.stdin.readlines():
	for line in fd:
	#if line == '\n':
	#if re.match("^( |\t)*\n$", line):
		#print "STRING \"%s\" matches."%line
		#continue
	#print line
		if re.match("^ *#", line):
			continue
		
		elif re.match("^( |\t)*$", line):
			continue

		elif re.match("^ *//", line):
			continue
	
		elif re.match("^ *extern ", line):
			continue
		else:
			# print line
			string_temp = string_temp + line
	
#print string_temp


#record comments "//" times 
	double_slash_commens = 0

#record "comments /* */" times
	star_comments = 0




#This part is used to get rid of all weird code comments line

	end_str = ""
	result = []
	i = 0
	while i < len(string_temp):
		if end_str and string_temp.startswith(end_str, i):
			i = i + len(end_str)
			end_str = ""
		elif end_str:
			i = i + 1
		elif string_temp[i : i + 2] == '//':
			end_str = '\n'
			i = i + 2
		elif string_temp[i : i + 2] == '/*':
			end_str = '*/'
			i = i + 2
		else:
			result.append(string_temp[i])
			i = i + 1
		
	string_temp = "".join(result)


#print string_temp



#for i in result:
	#print type (i)
	#string_temp = string_temp.join(i),

#print result
	
		
#for char in string_temp:
#        if char == '/':
#		if
#		




	list_string = string_temp.split('\n')

#print list_string

	string_temp = ""

	for item in list_string:
		string_temp = string_temp + item

	list_string = string_temp.split('\t')



	string_temp = ""
	for item in list_string:
		string_temp = string_temp + item
        #close file  
	fd.close()
	return string_temp


#lexer = shlex.shlex(string_temp)

#lexer = string_lexical(string_temp)



"""
temp = []


for token in lexer:
	#temp.append(repr(token))
	temp.append(token)		
print temp
"""
#print str(temp[0])

#print (temp[0] == repr('socket'))
#print (temp[0]  == 'socket')

#print simple_api_function_counter('bind', lexer)
#print simple_api_function_counter('socket', lexer)

#print simple_api_structure_counter('sockaddr_in', lexer)
#empty_char


#for char in string_temp:
#	print char

   
