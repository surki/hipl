
#Direcory_working.py file is for walking through all source and header files related to all 
#different application directories  
#Licence: GNU/GPL
#Authors:Tao Wan<twan@cc.hut.fi>

import os
from string_token import *
from file_input import *


"""
#with os.path.walk
def delete_backups(arg, dirname, names):
	for name in names:
		if name.endswith('~'):
			os.remove(os.path.join(dirname, name))

os.path.walk(os.environ['HOME'], delete_backups, None)

# with os.path, if (like me) you can never remember how os.path.walk works
def walk_tree_delete_backups(d):
	for name in os.listdir(d):
		path = os.path.join(d, name)
		if os.path.isdir(path):
			walk_tree_delete_backups(path)
		elif name.endswith('~'):
		os.remove(path)

walk_tree_delete_backups(os.environ['HOME'])

# with path
d = path(os.environ['HOME'])
	for f in d.walkfiles('*~'):
	f.remove()

"""

# with os.path, if (like me) you can never remember how os.path.walk works
#print all .cpp or .c or .cc , cp, c++, .h file
def walk_tree_print_c_files(d, constants, functions, structures, dic_whole_api):
	for name in os.listdir(d):
		path = os.path.join(d, name)
		if os.path.isdir(path):
			walk_tree_print_c_files(path, constants, functions, structures, dic_whole_api)
		elif (name.endswith('.c') or name.endswith('.cpp') or  name.endswith('.c++') or \
		  	name.endswith('.cc') or name.endswith('.cpp') or name.endswith('.h')):
			#print path
			file_token = readFile(path)
			api_counter(constants, functions, structures, file_token, dic_whole_api)



# return all dirs name under the "applications" directory which save all network (internet) application
def dirs_under_applications():
	pass



#walk_tree_print_c_files(os.path.join(os.environ['PWD'],'applications'))


