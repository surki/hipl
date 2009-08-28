import os, sys
import apsw
import shutil
from conf_reader import ConfReader
#from pysqlite2 import dbapi2 as sqlite

#reference: http://www.initd.org/pub/software/pysqlite/apsw/3.3.13-r1/apsw.html


###
### Check we have the expected version of apsw and sqlite
###

class dbHandle:

	def __init__(self, cons_list, func_list, struc_list, apps_list):

		print "Using APSW file",apsw.__file__     # from the extension module
		print "APSW version",apsw.apswversion()  # from the extension module
		print "SQLite version",apsw.sqlitelibversion()  # from the sqlite library code



###
### Opening/creating database, initialize database
###             
		self.apsw_version = apsw.apswversion()
		self.release_number = self.apsw_version[4:6]
		
		self.db_path = os.path.join(os.environ['PWD'],'db')
		#self.confReader = ConfReader('sockets_analysis.conf')

		#self.functions = self.confReader.getItems('functions')
		#self.structures = self.confReader.getItems('structures')
		
		self.functions = func_list
		self.structures = struc_list
		self.constants = cons_list
		function_temp = ""
		
		structure_temp = ""
		constant_temp = ""

		for constant in self.constants:
			constant_temp = constant_temp + constant[0].strip() + " int,"
		
		for function in self.functions:
			function_temp = function_temp + function[0].strip() + " int,"

		i = 0
		len_item = len(self.structures) # length of items 
		for structure in self.structures:
			if i < len_item - 1:
				structure_temp = structure_temp + structure[0].strip() + " int,"
			else:
				structure_temp = structure_temp + structure[0].strip() + " int"

			i = i + 1
		
		creat_table = "CREATE TABLE socket_statistic (name varchar PRIMARY KEY, " + constant_temp + function_temp  + structure_temp + ")"
		creat_sum_table =  "CREATE TABLE socket_statistic_sum (socket_api_name varchar PRIMARY KEY , sum_number int)"
		
		print creat_table
		print creat_sum_table

		#print creat_table		
		
		

		if os.path.exists(self.db_path): 
			print "database path existing......" 
			#print "delete the existing", self.db_path
			#shutil.rmtree(self.db_path) #Removes directories recursively
			#pass
		
		else:
			print "create the db directory"
			os.mkdir('db')
		database_file =  os.path.join(self.db_path, 'socket_analysis_data_sos.db')
		self.connection=apsw.Connection(database_file)
		self.cursor=self.connection.cursor()
		
		"""
		self.cursor.execute(creat_table)		
		"""
		
		try:
			self.cursor.execute(creat_table)		
		except:
			print "socket_statistic table is already there or something wrong with creating DB!!!"


		try:
			self.cursor.execute(creat_sum_table)		
		except:
			print "socket_statistic_sum table is already there or something wrong with creating DB!!!"
		#Create table



		


###
### Cleanup
###


#work only with apsw version 3.3.13-r1 
# We must close connections
	def close(self):
		
		try:
			release_number = int(self.release_number)		
		except:
			return 
		
		if release_number >= 13 : # check the version number
			self.connection.close()  # force it since we want to exit

#get all application whose socket API analysis is done or not according to database

	def apps_analysis_is_done(self):
		apps_analysis_is_done = [] 
		for app_names in self.cursor.execute("select name from socket_statistic"):
   			print app_names
			for app_name in app_names:
				apps_analysis_is_done.append(app_name)
		#print apps_analysis_is_done
		return apps_analysis_is_done


#check application is already ananlysed or not? reutrn True or false
	def is_analysis(self, app, apps_in_db):
		for apps_list in apps_in_db:
			if app in apps_list:
				return True
		return False 


#insert analysis data based on each application.
#SQL insert syntax:INSERT INTO table_name (column1, column2,...) VALUES (value1, value2,....)
	def insert_analysis_data(self, app_name, apps_api_counter_dic): 
		#for items in apps_api_counter_dic:
		apps_api_counter_dic.update({'name':app_name})
		print apps_api_counter_dic
		#self.cursor.execute("insert into socket_statistic(:name, :connect, :recvfrom, :socket, :in_addr, :sockaddr, :bind, :sockaddr_in, :sockaddr_in6, :accept, :write, :send, :sendto, :sockadd_storage, :close, :recv, :in6_addr, :listen)", apps_api_counter_dic)
		insert_sql = "insert into socket_statistic("

		column_name = ""
		values = ""
		for item in apps_api_counter_dic:
			column_name = column_name + item + ", "
			if isinstance(apps_api_counter_dic[item], (int)):#is int or not
				temp_string = str(apps_api_counter_dic[item])
			else:
				temp_string = "'" + apps_api_counter_dic[item] + "'"
			values = values + temp_string  + ", "
		
		len_table = len(column_name)
		len_values = len(values)

		column_name = column_name[0:len_table - 2]
		values = values[0:len_values - 2]
		
		insert_sql = insert_sql + column_name + ") VALUES (" + values + ")"
		print insert_sql


		self.cursor.execute(insert_sql)

# Insert sum to socket_statistic_sum and sort it.

	def insert_sum_data(self):
		apps_analysis_is_done = [] 
		for app_names in self.cursor.execute("select name from socket_statistic"):
   			print app_names
			for app_name in app_names:
				apps_analysis_is_done.append(app_name)
	
		insert_sql_sum = "insert into socket_statistic_sum (socket_api_name , sum_number) VALUES ("
		print insert_sql_sum
		
		
			
		for constant in self.constants:
			#for app_name in apps_analysis_is_done:
			#print app_name
			select_sum_command = "select " + "SUM" + "(" +  constant[0].strip() + ")"  + " from socket_statistic"
			print select_sum_command
			sum = self.cursor.execute(select_sum_command)
			for sum_number in sum:
				print sum_number[0]
				
			insert_sql_temp = insert_sql_sum + "'" + constant[0].strip() + "'"", " + str(sum_number[0]).strip() + ")"
			print insert_sql_temp
			
			try:
				self.cursor.execute(insert_sql_temp)
			except:
				continue
		for  function in self.functions:
			#for app_name in apps_analysis_is_done:
			#	print app_name	
			select_sum_command = "select " + "SUM" + "(" +  function[0].strip() + ")"  + " from socket_statistic"
			print select_sum_command
			sum = self.cursor.execute(select_sum_command)
			for sum_number in sum:
				print sum_number[0]
			insert_sql_temp = insert_sql_sum + "'" + function[0].strip() + "'" +  ", " + str(sum_number[0]).strip() + ")"
			print insert_sql_temp
			
			try:
				self.cursor.execute(insert_sql_temp)
			except:
				continue
		for structure in self.structures:
			#for app_name in apps_analysis_is_done:
				#print app_name
			select_sum_command = "select " + "SUM" + "(" +  structure[0].strip() + ")"  + " from socket_statistic"
			print select_sum_command
			sum = self.cursor.execute(select_sum_command)
			for sum_number in sum:
				print sum_number[0]
			insert_sql_temp = insert_sql_sum + "'" + structure[0].strip() + "'" + ", " + str(sum_number[0]).strip() + ")"
			print insert_sql_temp
			try:
				self.cursor.execute(insert_sql_temp)
			except:
				continue







###
### simple statement
###

#cursor.execute("create table foo(x,y,z)")

###
### multiple statements
###



