from conf_reader import ConfReader
from search_engine import SearchEngine
from file_input import *
from directory_walking import *
from fetch_files import fetchNetApps
from database_engine import dbHandle


#reader = ConfReader('sockets_API.conf')
reader = ConfReader('sockets_analysis.conf')

#reader.print_test()

#print reader.getValue('functions', 'socket')
#print reader.getItems('functions')
#print reader.getItems('structures')

functions = reader.getItems('functions')
structures = reader.getItems('structures')
applications = reader.getItems('applications')

#print applications

#all = reader.getItems('functions') + reader.getItems('structures')
all = functions + structures



fetchnetapps = fetchNetApps(applications)
fetchnetapps.download_apps()
fetchnetapps.decompress_apps()

dbhandle = dbHandle(functions, structures, applications)

"""
reader.saveItemsDic('functions')
reader.saveItemsDic('structures')
dic = reader.getDicContainer()
#print dic['socket']
#print dic['bind']

print all
"""

search_engine = SearchEngine(all)
#search_engine.update_function_call_counters('socket', 4)
#search_engine.print_counts()

#string_temp = readFile('test.c')

#print "----------------------------------------"

#api_counter(functions, structures, string_temp, search_engine)
#search_engine.print_counts()



#temp = string_lexical(string_temp) 
#print simple_api_function_counter('sendto', temp)

#api_counter(functions, structures, string_temp, search_engine)



#count all socket APIs under applications directory
apps_dir = os.path.join(os.environ['PWD'],'applications')

for name in os.listdir(apps_dir):
	path = os.path.join(apps_dir, name)
	for conf_name in applications:
		if conf_name[0].lower() in name.lower():
			print conf_name[0]
		      	app_name = conf_name[0]
			break
				
	
	if os.path.isdir(path):
   		walk_tree_print_c_files(path, functions, structures, search_engine)
		print "application is ", path
		search_engine.print_counts()
		apps_api_counter_dic = search_engine.get_counts()
		dbhandle.insert_analysis_data(app_name,  apps_api_counter_dic)		

	del search_engine
	search_engine = SearchEngine(all)


#walk_tree_print_c_files(apps_dir, functions, structures,search_engine)

#search_engine.print_counts()



dbhandle.close()

