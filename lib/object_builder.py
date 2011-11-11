__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import simplejson as json
import sys
import urllib
import urllib2
import os
from time import time
import pdfid_mod
import hashlib
import hash_maker
import optparse
import traceback
from harness import *
import time as other_time

def get_vt_obj(file):
	try:
		key = 'YOUR_API_KEY'
		url = "https://www.virustotal.com/api/get_file_report.json"
		parameters = {"resource": file, "key": key}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		vtobj = response.read()

		preprocess = json.loads(vtobj)
		report = preprocess.get("report")
		permalink = preprocess.get("permalink")
		result = preprocess.get("result")

		if int(result) == 1:
			scanners = []
			last_scan = report[0]
			for k, v in report[1].iteritems():
				scanner = { 'antivirus' : k, 'signature' : v }
				scanners.append(scanner)

			vtobj = { 'report' : { 'last_scan':last_scan, 'permalink':permalink, 'results' : { 'scanners' : scanners } } }
		else:
			vtobj = { 'report' : { 'results': {'scanners' : [] } } }
	
	except:
		print "VT failed for " + str(file)
		vtobj = { 'report' : { 'results': {'scanners' : [] } } }

	return json.dumps(vtobj)
	
def get_structure(file):
	structureobj = pdfid_mod.PDFiD(file,True)
	return structureobj

def get_hash_obj(file):
	hashes = hash_maker.get_hash_object(file)
	data = { 'file': hashes }
	return json.dumps(data)	
	
def get_contents_obj(file):
	objcontents = json.loads(snatch_contents(file))
	data = { 'objects': objcontents }
	return json.dumps(data)	

def get_version_details(file):
	objcontents = json.loads(snatch_version(file))
	return json.dumps(objcontents)

def build_obj(file, dir=''):

	if dir != '':
		file = dir + file

	frelated = "null"
	
	try:
		vt_hash = hash_maker.get_hash_data(file, "md5")
	except:	
		print str(traceback.print_exc())
		print "VT Hash error"
	
	try:
		fhashes = json.loads(get_hash_obj(file))
	except:	
		print str(traceback.print_exc())
		print "Hash error"
	
	try:
		fstructure = json.loads(get_structure(file))
	except:	
		print str(traceback.print_exc())
		print "Structure error"
	
	try:
		fvt = json.loads(get_vt_obj(vt_hash))
	except:	
		print str(traceback.print_exc())
		print "VT error"
	
	try:
		fversion = json.loads(get_version_details(file))
	except:	
		print str(traceback.print_exc())
		print "Versions error"
	
	try:
		fcontents = json.loads(get_contents_obj(file))
	except:	
		print str(traceback.print_exc())
		print "Content error"


	#build the object and then re-encode

	try:
		fobj = { "hash_data": fhashes, "structure": fstructure, "scans": { "virustotal": fvt, "wepawet": "null" }, "contents" : fcontents, 'versions': fversion, 'tags': ['public'] }
	except:
		print "Obj error"
		print str(traceback.print_exc())

	return json.dumps(fobj)
