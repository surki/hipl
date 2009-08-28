# string_token.py file is for handling all string related functionality
#Licence: GNU/GPL
#Authors: 
#Tao Wan<twan@cc.hut.fi>


#!/usr/bin/python
import shlex
import string


"""
Take the whole string as a parameter, return a token strings
"""
def string_lexical(string_needs_parse):
	lexer = shlex.shlex(string_needs_parse)
	temp = []
	#do not know what to do when shlex raises exception 
	try:
		for token in lexer:
                	temp.append(token)
	except:
		return temp	
	return temp




"""
added on 15 July, 2008, simple socket API - constant counter function,
The purpose is to counter the times of all socket API constants like 
AF_INET and AF_INET6.

The C programming languge sysntax is like:
   int example = AF_INET;
   int socket(AF_INET6, SOCKET_STREAM, IPPROTO_TCP);

"""
def simple_api_constant_counter(api_name, token_list):
	i = 0
	counter = 0


	#count the length of token lsit 
	length_list = len(token_list)

	#print length_list
	
	temp = token_list

	#print api_name
	for strings in temp:
		if(i == 0):
			i = i + 1
			continue
		else:
			if(strings == api_name) and (temp[i-1]) == '=' and (temp[i+1] == ';'):
			#Try to get the first letter is capital(upper case) for being 
			#sure that the string is constant
				if str.isupper(strings[:1]):
					counter = counter + 1
			elif(strings == api_name) and (temp[i-1]) == '(' and (temp[i+1] == ','):
				if str.isupper(strings[:1]):
					counter = counter + 1
			elif(strings == api_name) and (temp[i-1]) == ',' and (temp[i+1] == ','):
				if str.isupper(strings[:1]):
					counter = counter + 1
			elif(strings == api_name) and (temp[i-1]) == ',' and (temp[i+1] == ')'):
				if str.isupper(strings[:1]):
					counter = counter + 1
		i = i + 1
		
	return counter
"""
simple counter for socket API, for a function call like 
function socket call, its previous chars should be ";"," = " , "nothing" or 
"}",its after_char should be char "(" 
"""
def simple_api_function_counter(api_name, token_list):
	#previous_chars = ""
	#after_chars = ""
	i = 0
	counter = 0
	
	length_list = len(token_list)
	
	#print length_list
	
	#print length_list
	
	temp = token_list
	for strings in temp:
		if (i == 0):
			if (strings == api_name) and (temp[i+1] == '('):
				counter = counter + 1
		
		elif (i == (length_list - 1)):
			continue		
    		else:
			if ((strings == api_name) and \
			(temp[i - 1] == ';' or (temp[i - 1] == '=') or (temp[i - 1] == '(')  or  temp[i - 1] == ','  or (temp[i - 1] == '}')) \
			and (temp[i+1] == '(')):
				counter = counter + 1
		i = i + 1

	return counter

"""
simple counter for structure declarations, for a structure declaration like 
sructure , its previous chars should be "struct" ,its after_char should be anything
"""

def simple_api_structure_counter(api_name, token_list):
	i = 0
	counter = 0
	
	length_list = len(token_list)
	temp = token_list
	
	for strings in temp:
		#BUGGY here? how to make strong the "if" condition for getting
		# the correct "struct" declaration.
		#example: struct oops* 
		#example: struct oops**
		
		if (i == 0):
			continue
		
		if ((api_name in strings) and ('struct' in temp[i - 1])):
			counter = counter + 1
		i = i + 1
	return counter
	
"""
Complicated counter for socket API, for a function call like 
function socket call and also structure declare.  Function calls its previous chars should be ";"," = " , "nothing" or 
"}",its after_char should be char "(" . structure declaration its previous should struct.  

input: para@api_funtion_call name lists, @api_structure_declarations, file token list, dictionary of whole api call
output: all different counters based on api names, updated dicionary of whole api call
"""

def api_counter(api_constants_used, api_function_calls, api_structure_declarations, file_token, dic_whole_api):
	
	string_temp = string_lexical(file_token)	

	#print string_temp
	
	for api_constant in api_constants_used:
		temp = simple_api_constant_counter(api_constant[1], string_temp)
		
		dic_whole_api.update_function_call_counters(api_constant[0], temp)
	

	for api_function_call in api_function_calls:
		temp = simple_api_function_counter(api_function_call[1], string_temp)
		
		#print api_function_call[0], temp
		
		dic_whole_api.update_function_call_counters(api_function_call[0], temp)
        
	for api_structure_declaration in api_structure_declarations:
		temp = simple_api_structure_counter(api_structure_declaration[1], string_temp)
		#print  api_structure_declaration[0], temp
		
		dic_whole_api.update_function_call_counters(api_structure_declaration[0], temp)
	#print dic_whole_api.print_counts()

         





