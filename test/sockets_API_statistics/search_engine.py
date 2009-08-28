#this search engine includes all search related functions

#Licence: GNU/GPL
#Authors: 
#Tao Wan<twan@cc.hut.fi>

#!/usr/bin/python

class SearchEngine:
	
	#initialize counter for all keys
	def __init__(self, list_conf):
		self.function_call_counters = {} 

		for pair in list_conf:
			print pair
                        #initialize each counter of different function calls to be zero 
                        self.function_call_counters[pair[0]] = 0

	
	#update counter numbers according to keyword
	def update_function_call_counters(self, keyword, num):
		if (keyword in self.function_call_counters):
			self.function_call_counters[keyword] =  self.function_call_counters[keyword] + num
	
			
	
	def print_counts(self):
		print self.function_call_counters

	def get_counts(self):
		return self.function_call_counters
	
	def getCodeLine(self, counts_list, dic_conf, line):
		pass
		

