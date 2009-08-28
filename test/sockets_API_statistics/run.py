from conf_reader import ConfReader
from search_engine import SearchEngine
from file_input import *
from directory_walking import *
from string_token import *
from fetch_files import fetchNetApps
from database_engine import dbHandle
import sys

reader = ConfReader('sockets_analysis.conf')


constants = reader.getItems('constants')
functions = reader.getItems('functions')
structures = reader.getItems('structures')
applications = reader.getItems('applications')

all_socket_api = constants + functions + structures 

"""
file_token = readFile("netstream.c")

# print file_token

string_temp = string_lexical(file_token)


#print string_temp



temp = simple_api_constant_counter("AF_INET", string_temp)

print temp


temp = simple_api_function_counter("socket", string_temp)

print temp
"""

fetchnetapps = fetchNetApps(applications)
fetchnetapps.download_apps()
fetchnetapps.decompress_apps()



dbhandle = dbHandle(constants, functions, structures, applications)

apps_in_analysis_db = dbhandle.apps_analysis_is_done()




search_engine = SearchEngine(all_socket_api)

#count all socket APIs under applications directory
apps_dir = os.path.join(os.environ['PWD'],'applications')


#buggy Here
#for name in os.listdir(apps_dir):
for conf_name in applications:	
	#check whether it is the right application download based on configuration file
	# FIX ME:  not try to get 
	#for conf_name in applications:
	for name in os.listdir(apps_dir):
		path = os.path.join(apps_dir, name)
		#print name
		#print conf_name
		if conf_name[0].lower() in name.lower():
			#print conf_name[0]
		      	app_name = conf_name[0]
			break
	print app_name
	
        
          
	
	if dbhandle.is_analysis(app_name, apps_in_analysis_db):
		print "application ", app_name, " has been analysed!!!"
		continue 

			
	
	if os.path.isdir(path):
   		walk_tree_print_c_files(path, constants, functions, structures, search_engine)
		print "application is ", path
		search_engine.print_counts()
		apps_api_counter_dic = search_engine.get_counts()
		dbhandle.insert_analysis_data(app_name,  apps_api_counter_dic)		

	
	del search_engine
	search_engine = SearchEngine(all_socket_api)



dbhandle.insert_sum_data()


#walk_tree_print_c_files(apps_dir, functions, structures,search_engine)

#search_engine.print_counts()

dbhandle.close()
sys.exit()


