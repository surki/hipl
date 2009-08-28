#This conf_reader file is used to read the configuration file called 
#sockets_API.conf. It saves all function calls and struct type data in a 
# dictionary.
#!/usr/bin/python
from ConfigParser import ConfigParser
import os


class ConfReader:
	def __init__(self, config_file):
	#def __init__(self):
		#PWD environment var is used in linux/unix OS. 
		#conf_filename = os.path.join(os.environ['PWD'], 'sockets_API.conf')
		conf_filename = os.path.join(os.environ['PWD'], config_file)
	#conf_filename = os.path.join(os.environ['HOME'], config_file)
		
		self.config = ConfigParser()
		self.config.add_section("constants")
		self.config.add_section("functions")
		self.config.add_section("structures")
		self.config.add_section("applications")
		#fname = open(conf_filename,"r")
		self.config.read([conf_filename])
		#Container for keeping all configuration file data. Initial value is empty   
		self.dicContainer = {}
		
		#self.config.readfp(fname)
		
	

	def print_test(self):
		#conf_filename = os.path.join(os.environ['HOME'], 'sockets_API.conf')
		#config = ConfigParser()
		#config.add_section("functions")
		print self.config.get("functions", "socket")


	def print_test2(self):
		print self.config.get("functions","socket")


	#get key value under the section
	def getValue(self, section, key):
		value = self.config.get(section, key)
		return value

	#get all items based on section
	def getItems(self, section):
		items = self.config.items(section)
		return items

	

#parse config file based on the section, save the items into dictionary
	def saveItemsDic(self, section):
		items = self.getItems(section)
		try:
			for item in items:
				#item[0] is key, item[1] is value
				self.dicContainer[item[0]] = item[1]
				"""
				print item[0]
				print item[1]
				"""
		except:
			print "Could get items based on section"
		#return self.dicContainer

# get the container which keeps all configuration file data.
	def getDicContainer(self):
		return self.dicContainer


