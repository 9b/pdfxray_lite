import simplejson as json
import codecs
import re

__author__ = "Brandon Dixon"
__email__ = "brandon@9bplus.com"

class jPdf():
	def __init__(self, raw_json):
		self._scores = None
		self._primary_score = None
		self._secondary_score = None
		self._total_score = None

		self._hash_data = None
		self._file_hashes = None
		self._file_md5 = None
		self._file_sha1 = None
		self._file_sha256 = None

		self._contents = None
		self._objs = []
		self._small_objs = []
		self._large_objs = []
		self._suspicious_objs = []
		self._robjs = []

		self._scans = None
		self._virustotal_report = None
		self._virustotal_last_scan = None
		self._virustotal_permalink = None
		self._virustotal_scan_results = None

		self._structure = None
		self._components = []
		self._keywords = []
		self._suspicious_keywords = []
		self._header = None
		self._filesize = None
		self._non_stream_entropy = None
		self._stream_entropy = None
		
		self._judgment = None
		
		self._versions_d = None
		self._versions = []
	
		#go forth and parse
		self.dump_data(raw_json)
		
		try:
			self.add_related(raw_json)
		except:
			failed = None

	def dump_data(self, raw_json):
		#top level
		#self._scores = self.shallow_diver(raw_json,"scores")
		self._hash_data = self.shallow_diver(raw_json,"hash_data")
		self._file_hashes = self.shallow_diver(self._hash_data,"file")
		self._contents = self.shallow_diver(raw_json,"contents")
		self._objects = self.shallow_diver(self._contents,"objects")
		self._scans = self.shallow_diver(raw_json,"scans")
		self._virustotal_report = self.shallow_diver(self._scans,"report")
		self._virustotal_results = self.shallow_diver(self._virustotal_report,"results")
		self._structure = self.shallow_diver(raw_json,"structure")
		self._components_d = self.shallow_diver(self._structure,"components")
		self._component = self.shallow_diver(self._components_d,"component")
		self._keywords_d = self.shallow_diver(self._structure,"keywords")
		self._keyword = self.shallow_diver(self._keywords_d,"keyword")
		self._versions_d = self.shallow_diver(raw_json,"versions")

		#hash_data
		self.set_hash_data(self._hash_data)
		self.set_file_hashes(self._file_hashes)
		self.set_file_md5(self._file_hashes.get("md5"))
		self.set_file_sha1(self._file_hashes.get("sha1"))
		self.set_file_sha256(self._file_hashes.get("sha256"))

		#contents
		self.set_contents(self._contents)
		self.process_objects(self._objects)
		self.set_objs(self._objs)
		self.set_small_objs(self._small_objs)
		self.set_large_objs(self._large_objs)
		self.set_suspicious_objs(self._suspicious_objs)
		self.set_robjs(self._robjs)

		#scans
		self.set_scans(self._scans)
		self.set_virustotal_report(self._virustotal_report)
		self.set_virustotal_last_scan(self._virustotal_report.get("last_scan"))
		self.set_virustotal_permalink(self._virustotal_report.get("permalink"))
		self.set_virustotal_scan_results(self._virustotal_results.get("scanners"))

		#structure
		self.set_structure(self._structure)
		self.set_header(self._structure.get("header"))
		self.set_filesize(self._structure.get("filesize"))
		self.set_non_stream_entropy(self._structure.get("nonStreamEntropy"))
		self.set_stream_entropy(self._structure.get("streamEntropy"))
		self.process_named_functions(self._component,"components")
		self.process_named_functions(self._keyword,"keywords")
		self.set_keywords(self._keywords)
		self.set_suspicious_keywords(self._suspicious_keywords)
		
		#versions
		self.process_versions(self._versions_d)

	def make_report(self,pdf,out):
		report = "<html><head><title>" + pdf.file_md5 + " Report</title><style type='text/css'>h2 {margin: 0;text-indent: 25px;} h2.sus {color:red;} h2.nor {color:blue;} h3 {margin: 0;text-indent: 50px;} p {margin: 0;text-indent: 75px;}</style></head><body>"
		report += "<h1><font color='orange'>PDF X-RAY</font></h1>"
		report += "<h1>General Information</h1>"
		report += "<p><b>MD5: </b>" + pdf.file_md5 + "</p>"
		report += "<p><b>SHA1: </b>" + pdf.file_sha1 + "</p>"
		report += "<p><b>SHA256: </b>" + pdf.file_sha256 + "</p>"
		report += "<p><b>PDF Header: </b>" + pdf.header + "</p>"
		report += "<p><b>File Size: </b>" + pdf.filesize + "</p>"
		report += "<br>"
		report += "<h2>Object Order</h2>"
		for obj in pdf.objs:
			report += "<p>Object: " + str(obj.id) + " : @offset " + str(obj.offset) + " : " + str(obj.size) + " bytes</p>"  
            
		report += "<h1>Versions</h1>"	
		for version in pdf.versions:
			report += "<h2>Version " + str(version.version) + "</h2>"
			report += "<h3>Author</h3>"
			report += "<p>" + version.author + "</p>"
			report += "<h3>Creator</h3>"	
			report += "<p>" + version.creator + "</p>"
			report += "<h3>Producer</h3>"
			report += "<p>" + version.producer + "</p>"
			report += "<h3>Creation Date</h3>"
			report += "<p>" + version.creation_date + "</p>"
			report += "<h3>Modification Date</h3>"
			report += "<p>" + version.modification_date + "</p>"    
            
		report += "<h1><font color='red'>Suspicious Objects</font></h1>"
		for obj in pdf.suspicious_objs:
			report += "<br><br>"
			report += "<h2 class='sus'>Object: " + str(obj.id) + " : @offset " + str(obj.offset) + " : " + str(obj.size) + " bytes</h2>"	
			report += "<h3>Raw Data</h3>"
			report += "<p>" + obj.raw + "</p>"
			report += "<h3>Raw Hash</h3>"
			report += "<p>" + obj.raw_hash + "</p>"
			report += "<h3>Encrypted?</h3>"
			report += "<p>" + str(obj.encrypted) + "</p>"
                    
			if obj.suspicious_actions:
				report += "<h3>Suspicious Actions</h3>"        
				for item in obj.suspicious_actions:
					report += "<p>" + item + "</p>"
            
			if obj.suspicious_elements:
				report += "<h3>Suspicious Elements</h3>"
				for item in obj.suspicious_elements:
					report += "<p>" + item + "</p>" 
            
			if obj.suspicious_events:
				report += "<h3>Suspicious Events</h3>"
				for item in obj.suspicious_events:
					report += "<p>" + item + "</p>"   
            
			if obj.vulns:
				report += "<h3>Vulnerabilities</h3>"
				for item in obj.vulns:
					report += "<p>" + item + "</p>"  
                    
			if len(obj.references) > 0:
				report += "<h3>References</h3>"
				report += "<p>" + ",".join(obj.references)
    
			if obj.stream:
				if obj.stream_decoded_stream:
					report += "<h3>Decoded Stream Hash</h3>"
					report += "<p>" + obj.stream_decoded_hash + "</p>"
					report += "<h3>Decoded Stream</h3>"
					report += "<p>" + obj.stream_decoded_stream + "</p>"
                           
		report += "<h1><font color='blue'>All Objects</font></h1>"
		for obj in pdf.objs:
			report += "<br><br>"
			report += "<h2 class='nor'>Object: " + str(obj.id) + " : @offset " + str(obj.offset) + " : " + str(obj.size) + " bytes</h2>"
			report += "<h3>Raw Data</h3>"
			report += "<p>" + obj.raw + "</p>"
			report += "<h3>Raw Hash</h3>"
			report += "<p>" + obj.raw_hash + "</p>"
			report += "<h3>Encrypted?</h3>"
			report += "<p>" + str(obj.encrypted) + "</p>"
                    
			if obj.suspicious_actions:
				report += "<h3>Suspicious Actions</h3>"        
				for item in obj.suspicious_actions:
					report += "<p>" + item + "</p>"
            
			if obj.suspicious_elements:
				report += "<h3>Suspicious Elements</h3>"
				for item in obj.suspicious_elements:
					report += "<p>" + item + "</p>" 
            
			if obj.suspicious_events:
				report += "<h3>Suspicious Events</h3>"
				for item in obj.suspicious_events:
					report += "<p>" + item + "</p>"   
            
			if obj.vulns:
				report += "<h3>Vulnerabilities</h3>"
				for item in obj.vulns:
					report += "<p>" + item + "</p>"  
                    
			if len(obj.references) > 0:
				report += "<h3>References</h3>"
				report += "<p>" + ",".join(obj.references)
    
			if obj.stream:
				if obj.stream_decoded_stream:
					report += "<h3>Decoded Stream Hash</h3>"
					report += "<p>" + obj.stream_decoded_hash + "</p>"
					report += "<h3>Decoded Stream</h3>"
					report += "<p>" + obj.stream_decoded_stream + "</p>"
                    
		report += "</body></html>"
       
		f = codecs.open(out + pdf.file_md5 + "_report.html", encoding='utf-8', mode='w')
		f.write(report)
		f.close()		

	def process_versions(self,raw_json):
		for obj in raw_json:
			iversion = jVersion(obj)
			self._versions.append(iversion)

	def process_objects(self,json):
		for obj in json:
			iobj = jObj(obj)
			if iobj.size > 650:
				self._large_objs.append(iobj)
			else:
				self._small_objs.append(iobj)
				
			if len(iobj.vulns) > 0 or len(iobj.suspicious_actions) > 0 or len(iobj.suspicious_elements) > 0 or len(iobj.suspicious_events) > 0 or iobj.contains_js == True:
				self._suspicious_objs.append(iobj)
				
			self._objs.append(iobj)
		#self._objs.sort(key=lambda x: x.length, reverse=True)

	def process_named_functions(self,json,type):
		for named_function in json:
			inamed_function = jNamedFunctions(named_function)
			if type == "components":
				self._components.append(inamed_function)
			else:
				if inamed_function.hex_count > 0 or inamed_function.name == "/JS" or inamed_function.name == "/JavaScript" or inamed_function.name == "/AA" or inamed_function.name == "/OpenAction" or inamed_function.name == "/JBIG2Decode" or inamed_function.name == "/EmbeddedFile":
					self._suspicious_keywords.append(inamed_function)
					
				self._keywords.append(inamed_function)
		#self._keywords.sort(key=lambda x: x.hex_count, reverse=True)	
		
	def add_related(self,json):
		related = json.get("related")
		objects = related.get("objects")
		for related in objects:
			irobj = rObj(related)
			self._robjs.append(irobj)
				
	#setters
	def set_scores(self,scores):
		self._scores = scores
	def set_primary_score(self,primary):
		self._primary_score = primary
	def set_secondary_score(self,secondary):
		self._secondary_score = secondary
	def set_total_score(self,total):
		self._total_score = total

	def set_hash_data(self,hash_data):
		self._hash_data = hash_data
	def set_file_hashes(self,file_hashes):
		self._file_hashes = file_hashes
	def set_file_md5(self,file_md5):
		self._file_md5 = file_md5
        def set_file_sha1(self,file_sha1):
                self._file_sha1 = file_sha1
        def set_file_sha256(self,file_sha256):
                self._file_sha256 = file_sha256

	def set_contents(self,contents):
		self._contents = contents
	def set_objs(self,objs):
		self._objs = objs
	def set_small_objs(self,small_objs):
		self._small_objs = small_objs
	def set_large_objs(self,large_objs):
		self._large_objs = large_objs
	def set_suspicious_objs(self,suspicious_objs):
		self._suspicious_objs = suspicious_objs
	def set_robjs(self,robjs):
		self._robjs = robjs

	def set_scans(self,scans):
		self._scans = scans
	def set_virustotal_report(self,virustotal_report):
		self._virustotal_report = virustotal_report
	def set_virustotal_last_scan(self,virustotal_last_scan):
		self._virustotal_last_scan = virustotal_last_scan
	def set_virustotal_permalink(self,virustotal_permalink):
		self._virustotal_permalink = virustotal_permalink
	def set_virustotal_scan_results(self,virustotal_scan_results):
		self._virustotal_scan_results = virustotal_scan_results

	def set_structure(self,structure):
		self._structure = structure
	def set_components(self,components):
		self._components = components
	def set_keywords(self,keywords):
		self._keywords = keywords
	def set_suspicious_keywords(self,suspicious_keywords):
		self._suspicious_keywords = suspicious_keywords
	def set_header(self,header):
		self._header = header
	def set_filesize(self,filesize):
		self._filesize = filesize
	def set_non_stream_entropy(self,non_stream_entropy):
		self._non_stream_entropy = non_stream_entropy
	def set_stream_entropy(self,stream_entropy):
		self._stream_entropy = stream_entropy
		
	def set_judgement(self,judgement):
		self._judgement = judgement

	def set_versions(self,versions):
		self._versions = versions
		
	#getters
	def get_scores(self):
		return self._scores
	def get_primary_score(self):
		return self._primary_score
	def get_secondary_score(self):
		return self._secondary_score
	def get_total_score(self):
		return self._total_score

	def get_hash_data(self):
		return self._hash_data
	def get_file_hashes(self):
		return self._file_hashes
	def get_file_md5(self):
		return self._file_md5
	def get_file_sha1(self):
		return self._file_sha1
	def get_file_sha256(self):
		return self._file_sha256

	def get_contents(self):
		return self._contents
	def get_objs(self):
		return self._objs
	def get_small_objs(self):
		return self._small_objs
	def get_large_objs(self):
		return self._large_objs
	def get_suspicious_objs(self):
		return self._suspicious_objs
	def get_robjs(self):
		return self._robjs

	def get_scans(self):
		return self._scans
	def get_virustotal_report(self):
		return self._virustotal_report
	def get_virustotal_last_scan(self):
		return self._virustotal_last_scan
	def get_virustotal_permalink(self):
		return self._virustotal_permalink
	def get_virustotal_scan_results(self):
		return self._virustotal_scan_results

	def get_structure(self):
		return self._structure
	def get_components(self):
		return self._components
	def get_keywords(self):
		return self._keywords
	def get_suspicious_keywords(self):
		return self._suspicious_keywords
	def get_header(self):
		return self._header
	def get_filesize(self):
		return self._filesize
	def get_non_stream_entropy(self):
		return self._non_stream_entropy
	def get_stream_entropy(self):
		return self._stream_entropy
	
	def get_judgement(self):
		return self._judgement
	
	def get_versions(self):
		return self._versions

	#properties
	scores = property(get_scores,set_scores)
	primary_score = property(get_primary_score,set_primary_score)
	secondary_score = property(get_secondary_score,set_secondary_score)
	total_score = property(get_total_score,set_total_score)

	hash_data = property(get_hash_data,set_hash_data)
	file_hashes = property(get_file_hashes,set_file_hashes)
	file_md5 = property(get_file_md5,set_file_md5)
	file_sha1 = property(get_file_sha1,set_file_sha1)
	file_sha256 = property(get_file_sha256,set_file_sha256)

	contents = property(get_contents,set_contents)
	objs = property(get_objs,set_objs)
	small_objs = property(get_small_objs,set_small_objs)
	large_objs = property(get_large_objs,set_large_objs)
	suspicious_objs = property(get_suspicious_objs,set_suspicious_objs)
	robjs = property(get_robjs,set_robjs)

	scans = property(get_scans,set_scans)
	virustotal_report = property(get_virustotal_report,set_virustotal_report)
	virustotal_last_scan = property(get_virustotal_last_scan,set_virustotal_last_scan)
	virustotal_permalink = property(get_virustotal_permalink,set_virustotal_permalink)
	virustotal_scan_results = property(get_virustotal_scan_results,set_virustotal_scan_results)

	structure = property(get_structure,set_structure)
	components = property(get_components,set_components)
	keywords = property(get_keywords,set_keywords)
	suspicious_keywords = property(get_suspicious_keywords,set_suspicious_keywords)
	header = property(get_header,set_header)
	filesize = property(get_filesize,set_filesize)
	non_stream_entropy = property(get_non_stream_entropy,set_non_stream_entropy)
	stream_entropy = property(get_stream_entropy,set_stream_entropy)
	
	judgement = property(get_judgement,set_judgement)
	
	versions = property(get_versions,set_versions)

	#Grab objects at the top level or second level
	def shallow_diver(self,json,shell):
        	for key, value in json.iteritems():
	               	if shell == key:
                        	data = json.get(shell)
	                        break
        	        else:
                	        if shell in value:
                        	        data = json.get(key)
                                	data = self.shallow_diver(data,shell)

	        return data


class jObj():
	def __init__(self,raw_json):
		self._objs = []

		self._contains_js = None
		self._errors = []
		self._stream = None
		self._stream_decoded_hash = None
		self._stream_decoded_hex = None
		self._stream_decoded_stream = None
		self._stream_decoded_errors = None
		self._stream_encoded_hash = None
		self._stream_encoded_hex = None
		self._stream_encoded_stream = None
		self._stream_filter = None
		self._stream_js_code = []
		self._stream_size = None
		self._stream_flags = []
		self._stream_processed_flags = []
		self._raw_hash = None
		self._vulns = []
		self._encrypted = None
		self._suspicious_actions = []
		self._suspicious_elements = []
		self._suspicious_events = []
		self._raw = None
		self._references = []
		self._offset = None
		self._id = None
		self._size = None
		self._flag_users = []
		self._flagged_malicious = 0
		self._flagged_non_malicious = 0
		
		self.dump_data(raw_json)

	def dump_data(self,json):
                self._contains_js = json.get("contains_js")
                self._errors = json.get("errors")
		self._stream = json.get("stream")
		if len(self._stream) > 0:
			self._stream_decoded_hash = self._stream.get("decoded_hash")
			self._stream_decoded_hex = self._stream.get("decoded_hex")
			self._stream_decoded_stream = self._stream.get("decoded_stream")
			self._stream_decoded_errors = self._stream.get("decoded_errors")
			self._stream_encoded_hash = self._stream.get("encoded_hash")
			self._stream_encoded_hex = self._stream.get("encoded_hex")
			self._stream_encoded_stream = self._stream.get("encoded_stream")
			self._stream_filter = self._stream.get("filter")
			self._stream_js_code = self._stream.get("js_code")
			self._stream_size = self._stream.get("size")
			self._stream_flags = self._stream.get("flags")
                self._raw_hash = json.get("raw_hash")
                self._vulns = json.get("vulns")
                self._encrypted = json.get("encrypted")
                self._suspicious_actions = json.get("suspicious_actions")
                self._suspicious_elements = json.get("suspicious_elements")
                self._suspicious_events = json.get("suspicious_events")
                self._raw = json.get("raw")
                self._references = json.get("references")
                self._offset = json.get("offset")
                self._id = json.get("id")
		self._size = json.get("size")

		self.process_flags(self._stream_flags)

	def process_flags(self,flags):
		if len(flags) > 0:
			for item in flags:
				iflag = oFlag(item)
				self._flag_users.append(iflag.user)
				if iflag.malicious == "true":
					self._flagged_malicious += 1
				else:
					self._flagged_non_malicious += 1
				self._stream_processed_flags.append(iflag)

	def set_contains_js(self,contains_js):
		self._contains_js = contains_js
	def set_errors(self,errors):
		if len(errors) > 0:
			for item in errors:
				self._errors.append(item)
	def set_stream(self,stream):
		self._stream = stream
	def set_stream_decoded_hash(self,stream_decoded_hash):
		self._stream_decoded_hash = stream_decoded_hash
	def set_stream_decoded_hex(self,stream_decoded_hex):
		self._stream_decoded_hex = stream_decoded_hex
	def set_stream_decoded_stream(self,stream_decoded_stream):
		self._stream_decoded_stream = stream_decoded_stream
	def set_stream_decoded_errors(self,stream_decoded_errors):
		self._stream_decoded_errors = stream_decoded_errors
	def set_stream_encoded_hash(self,stream_encoded_hash):
		self._stream_encoded_hash = stream_encoded_hash
	def set_stream_encoded_hex(self,stream_encoded_hex):
		self._stream_encoded_hex = stream_encoded_hex
	def set_stream_encoded_stream(self,stream_encoded_stream):
		self._stream_encoded_stream = stream_encoded_stream
	def set_stream_filter(self,stream_filter):
		self._stream_filter = stream_filter
	def set_stream_js_code(self,stream_js_code):
		if len(stream_js_code) > 0:
			for item in stream_js_code:
				self._stream_js_code.append(item)
	def set_stream_size(self,stream_size):
		self._stream_size = stream_size
	def set_stream_flags(self,flags):
		if len(flags) > 0:
			for item in flags:
				iflag = oFlag(item)
				self._stream_processed_flags.append(iflag)
	def set_raw_hash(self,raw_hash):
		self._raw_hash = raw_hash
	def set_vulns(self,vulns):
		if len(vulns) > 0:
			for item in vulns:
				self._vulns.append(item)
	def set_encrypted(self,encrypted):
		self._encrypted = encrypted
	def set_suspicious_actions(self,suspicious_actions):
		if len(suspicious_actions) > 0:
			for item in suspicious_actions:
				self._suspicious_actions.append(item)
	def set_suspicious_elements(self,suspicious_elements):
		if len(suspicious_elements) > 0:
			for item in suspicious_elements:
				self._suspicious_elements.append(item)
	def set_suspicious_events(self,suspicious_events):
		if len(suspicious_events) > 0:
			for item in suspicious_events:
				self._suspicious_events.append(item)
	def set_raw(self,raw):
		self._raw = raw
	def set_references(self,references):
		if len(references) > 0:
			for item in references:
				self._references.append(item)
	def set_offset(self,offset):
		self._offset = offset
	def set_id(self,id):
		self._id = id
	def set_size(self,size):
		self._size = size
		
	def set_flag_users(self,flag_users):
		if len(flag_users) > 0:
			for item in flag_users:
				self._flag_users.append(item)
	def set_flagged_malicious(self,number):
		self._flagged_malicious += number
	def set_flagged_non_malicious(self,number):
		self._flagged_non_malicious += number
		
	def get_contains_js(self):
		return self._contains_js
	def get_errors(self):
		return self._errors
	def get_stream(self):
		return self._stream
	def get_stream_decoded_hash(self):
		return self._stream_decoded_hash
	def get_stream_decoded_hex(self):
		return self._stream_decoded_hex
	def get_stream_decoded_stream(self):
		return self._stream_decoded_stream
	def get_stream_decoded_errors(self):
		return self._stream_decoded_errors
	def get_stream_encoded_hash(self):
		return self._stream_encoded_hash
	def get_stream_encoded_hex(self):
		return self._stream_encoded_hex
	def get_stream_encoded_stream(self):
		return self._stream_encoded_stream
	def get_stream_filter(self):
		return self._stream_filter
	def get_stream_js_code(self):
		return self._stream_js_code
	def get_stream_size(self):
		return self._stream_size
	def get_stream_flags(self):
		return self._stream_flags
	def get_raw_hash(self):
		return self._raw_hash
	def get_vulns(self):
		return self._vulns
	def get_encrypted(self):
		return self._encrypted
	def get_suspicious_actions(self):
		return self._suspicious_actions
	def get_suspicious_elements(self):
		return self._suspicious_elements
	def get_suspicious_events(self):
		return self._suspicious_events
	def get_raw(self):
		return self._raw
	def get_references(self):
		return self._references
	def get_offset(self):
		return self._offset
	def get_id(self):
		return self._id
	def get_size(self):
		return self._size
	
	def get_flag_users(self):
		return self._flag_users
	def get_flagged_malicious(self):
		return self._flagged_malicious
	def get_flagged_non_malicious(self):
		return self._flagged_non_malicious
	
	contains_js = property(get_contains_js,set_contains_js)
	errors = property(get_errors,set_errors)
	stream = property(get_stream,set_stream)
	stream_decoded_hash = property(get_stream_decoded_hash,set_stream_decoded_hash)
	stream_decoded_hex = property(get_stream_decoded_hex,set_stream_decoded_hex)
	stream_decoded_stream = property(get_stream_decoded_stream,set_stream_decoded_stream)
	stream_decoded_errors = property(get_stream_decoded_errors,set_stream_decoded_errors)
	stream_encoded_hash = property(get_stream_encoded_hash,set_stream_encoded_hash)
	stream_encoded_hex = property(get_stream_encoded_hex,set_stream_encoded_hex)
	stream_encoded_stream = property(get_stream_encoded_stream,set_stream_encoded_stream)
	stream_filter = property(get_stream_filter,set_stream_filter)
	stream_js_code = property(get_stream_js_code,set_stream_js_code)
	stream_size = property(get_stream_size,set_stream_size)
	stream_flags = property(get_stream_flags,set_stream_flags)
	raw_hash = property(get_raw_hash,set_raw_hash)
	vulns = property(get_vulns,set_vulns)
	encrypted = property(get_encrypted,set_encrypted)
	suspicious_actions = property(get_suspicious_actions,set_suspicious_actions)
	suspicious_elements = property(get_suspicious_elements,set_suspicious_elements)
	suspicious_events = property(get_suspicious_events,set_suspicious_events)
	raw = property(get_raw,set_raw)
	references = property(get_references,set_references)
	offset = property(get_offset,set_offset)
	id = property(get_id,set_id)
	size = property(get_size,set_size)
	flag_users = property(get_flag_users,set_flag_users)
	flagged_malicious = property(get_flagged_malicious,set_flagged_malicious)
	flagged_non_malicious = property(get_flagged_non_malicious,set_flagged_non_malicious)
			
class jNamedFunctions():
	def __init__(self,raw_json):
		self._count = None
		self._hex_count = None
		self._name = None

		self.dump_data(raw_json)		
	
	def dump_data(self,json):
		self._count = json.get("count")
		self._hex_count = json.get("hexcodecount")
		self._name = json.get("name")

		self.set_count(self._count)
		self.set_hex_count(self._hex_count)
		self.set_name(self._name)

	def set_count(self,count):
		self._count = count
	def set_hex_count(self,hex_count):
		self._hex_count = hex_count
	def set_name(self,name):
		self._name = name

	def get_count(self):
		return self._count
	def get_hex_count(self):
		return self._hex_count
	def get_name(self):
		return self._name

	count = property(get_count,set_count)
	hex_count = property(get_hex_count,set_hex_count)
	name = property(get_name,set_name)

class rObj():
	def __init__(self,raw_json):
		self._obj_hash = None
		self._obj_id = None
		self._match = None
		self._matches = []

		self.dump_data(raw_json)

	def dump_data(self,json):
		self._obj_hash = json.get("sobj_hash")	
		self._obj_id = json.get("sobj_id")
		self._match = json.get("matches")
		self.process_matches(self._match)
		self.set_matches(self._matches)
		
	def process_matches(self,matches):
		for match in matches:
			imobj = mObj(match)
			self._matches.append(imobj)
		
	def set_obj_hash(self,obj_hash):
		self._obj_hash = obj_hash
	def set_obj_id(self,obj_id):
		self._obj_id = obj_id
	def set_matches(self,matches):
		self._matches = matches

	def get_obj_hash(self):
		return self._obj_hash
	def get_obj_id(self):
		return self._obj_id
	def get_matches(self):
		return self._matches

	obj_hash = property(get_obj_hash,set_obj_hash)
	obj_id = property(get_obj_id,set_obj_id)
	matches = property(get_matches,set_matches)
	
class mObj():
	def __init__(self,raw_json):
		self._parent_file_hash = None
		self._obj_hash = None
		self._obj_id = None
		
		self.dump_data(raw_json)

	def dump_data(self,json):
		self._parent_file_hash = json.get("parent_file_hash")
		self._obj_hash = json.get("mobj_hash")	
		self._obj_id = json.get("mobj_id")

	def set_parent_file_hash(self,parent_file_hash):
		self._parent_file_hash = parent_file_hash
	def set_obj_hash(self,obj_hash):
		self._obj_hash = obj_hash
	def set_obj_id(self,obj_id):
		self._obj_id = obj_id

	def get_parent_file_hash(self):
		return self._parent_file_hash
	def get_obj_hash(self):
		return self._obj_hash
	def get_obj_id(self):
		return self._obj_id
	
	parent_file_hash = property(get_parent_file_hash,set_parent_file_hash)
	obj_hash = property(get_obj_hash,set_obj_hash)
	obj_id = property(get_obj_id,set_obj_id)
	
class oFlag():
	def __init__(self,raw_json):
		self._user = None
		self._malicious = None
		
		self.dump_data(raw_json)

	def dump_data(self,raw_json):
		self._user = raw_json.get("user")
		self._malicious = raw_json.get("malicious")
		
	def set_user(self,user):
		self._user = user
	def set_malicious(self,malicious):
		self._malicious = malicious
		
	def get_user(self):
		return self._user
	def get_malicious(self):
		return self._malicious
	
	user = property(get_user,set_user)
	malicious = property(get_malicious,set_malicious)
	
class jVersion():
	def __init__(self,raw_json):
		self._version = None
		self._total_objects = None
		self._object_ids = None
		self._suspicious_actions_present = None
		self._suspicious_elements_present = None
		self._suspicious_events_present = None
		self._vulnerabilities_present = None
		self._author = None
		self._creator = None
		self._producer = None
		self._creation_date = None
		self._modification_date = None

		self.dump_data(raw_json)

	def dump_data(self,raw_json):
		self._version = raw_json.get("version")
		self._total_objects = raw_json.get("total_objects")
		self._object_ids = raw_json.get("object_ids")
		self._suspicious_actions_present = raw_json.get("suspicious_actions_present")
		self._suspicious_elements_present = raw_json.get("suspicious_elements_present")
		self._suspicious_events_present = raw_json.get("suspicious_events_present")
		self._vulnerabilities_present = raw_json.get("vulnerabilities_present")
		self._author = raw_json.get("author")
		self._creator = raw_json.get("creator")
		self._producer = raw_json.get("producer")
		self._creation_date = raw_json.get("creation_date")
		self._modification_date = raw_json.get("modification_date")

	def set_version(self,version):
		self._version = version
	def set_total_objects(self,total_objects):
		self._total_objects = total_objects
	def set_object_ids(self,object_ids):
		self._object_ids = object_ids
	def set_suspicious_actions_present(self,suspicious_actions_present):
		self._suspicious_actions_present = suspicious_actions_present
	def set_suspicious_elements_present(self,suspicious_elements_present):
		self._suspicious_elements_present = suspicious_elements_present
	def set_suspicious_events_present(self,suspicious_events_present):
		self._suspicious_events_present = suspicious_events_present
	def set_vulnerabilities_present(self,vulnerabilities_present):
		self._vulnerabilities_present = vulnerabilities_present
	def set_author(self,author):
		self._author = author
	def set_creator(self,creator):
		self._creator = creator
	def set_producer(self,producer):
		self._producer = producer
	def set_creation_date(self,creation_date):
		self._creation_date = creation_date
	def set_modification_date(self,modification_date):
		self._modification_date = modification_date

	def get_version(self):
		return self._version
	def get_total_objects(self):
		return self._total_objects
	def get_object_ids(self):
		return self._object_ids
	def get_suspicious_actions_present(self):
		return self._suspicious_actions_present
	def get_suspicious_elements_present(self):
		return self._suspicious_elements_present
	def get_suspicious_events_present(self):
		return self._suspicious_events_present
	def get_vulnerabilities_present(self):
		return self._vulnerabilities_present
	def get_author(self):
		return self._author
	def get_creator(self):
		return self._creator
	def get_producer(self):
		return self._producer
	def get_creation_date(self):
		return self._creation_date
	def get_modification_date(self):
		return self._modification_date

	version = property(get_version,set_version)
	total_objects = property(get_total_objects,set_total_objects)
	object_ids = property(get_object_ids,set_object_ids)
	suspicious_actions_present = property(get_suspicious_actions_present,set_suspicious_actions_present)
	suspicious_elements_present = property(get_suspicious_elements_present,set_suspicious_elements_present)
	suspicious_events_present = property(get_suspicious_events_present,set_suspicious_events_present)
	vulnerabilities_present = property(get_vulnerabilities_present,set_vulnerabilities_present)
	author = property(get_author,set_author)
	creator = property(get_creator,set_creator)
	producer = property(get_producer,set_producer)
	creation_date = property(get_creation_date,set_creation_date)
	modification_date = property(get_modification_date,set_modification_date)
