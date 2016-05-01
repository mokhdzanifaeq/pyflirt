from os.path import dirname
from ctypes import *
import zlib
import json

class header_v5(Structure):
	_pack_ = 1
	_fields_ = [
		("magic", c_char * 6),
		("version", c_ubyte),
		("arch", c_ubyte),
		("file_types", c_uint),
		("os_types", c_ushort),
		("app_types", c_ushort),
		("features", c_ushort),
		("old_n_functions", c_ushort),
		("crc16", c_ushort),
		("ctype", c_char * 12),
		("library_name_len", c_ubyte),
		("ctypes_crc16", c_ushort)
	]

class header_v6_v7(Structure):
	_fields_ = [
		("n_functions", c_uint)
	]

class header_v8_v9(Structure):
	_fields_ = [
		("pattern_size", c_ushort)
	]

class idasig:
	def __init__(self, binary, dump = False):
		self.binary = binary
		self.dump = dump
		with open(dirname(__file__) + "/flag/signature.json") as JSONdata:
		    self.flag = json.load(JSONdata)
		self.parse_flirt()

	def read_byte(self):
		byte = self.buffer[self.skip]
		self.skip += 1
		return ord(byte)

	def read_short(self):
		return (self.read_byte() << 8) + self.read_byte()

	def read_word(self):
		return (self.read_short() << 16) + self.read_short()

	def read_max_2_bytes(self):
		byte = self.read_byte()
		if byte & 0x80:
			return ((byte & 0x7f) << 8) + self.read_byte()
		return byte

	def read_multiple_bytes(self):
		byte = self.read_byte()
		if byte & 0x80 != 0x80:
			return byte
		if byte & 0xc0 != 0xc0:
			return ((byte & 0x7f) << 8) + self.read_byte();
		if byte & 0xe0 != 0xe0:
			return ((byte & 0x3f) << 24) + (self.read_byte() << 16) + self.read_short();
		return self.read_word()

	def parse_flirt(self):
		self.header = {}
		self.tree = {}
		self.skip = 0
		self.parse_header()
		if self.dump:
			self.dump_header()
		# check for compression
		if self.header["features"] & self.flag["features"]["COMPRESSED"]:
			# zlib(15) or deflate(-15)
			wbit = zlib.MAX_WBITS if ord(self.binary[self.skip]) == 0x78 else -zlib.MAX_WBITS
			self.buffer = zlib.decompress(self.binary[self.skip:], wbit)
		else:
			self.buffer = self.binary[self.skip:]
		self.skip = 0
		self.parse_tree(self.tree)

	def parse_header(self):
		v5 = header_v5.from_buffer_copy(self.binary)
		self.skip += sizeof(header_v5)
		for field_name, field_type in v5._fields_:
			self.header[field_name] = getattr(v5, field_name)
		if self.header["magic"] != "IDASGN":
			raise Exception("not a signature file")
		if self.header["version"] < 5 or self.header["version"] > 9:
			raise Exception("unsupported signature version")
		if self.header["version"] >= 6:
			v6_v7 = header_v6_v7.from_buffer_copy(self.binary[self.skip:])
			self.skip += sizeof(header_v6_v7)
			self.header["n_functions"] = v6_v7.n_functions
			if self.header["version"] >= 8:
				v8_v9 = header_v8_v9.from_buffer_copy(self.binary[self.skip:])
				self.skip += sizeof(header_v8_v9)
				self.header["pattern_size"] = v8_v9.pattern_size
		self.header["signature"] = self.binary[self.skip:self.skip+self.header["library_name_len"]].decode()
		self.skip += self.header["library_name_len"]

	def parse_tree(self, node):
		branches = self.read_multiple_bytes()
		# no branches == leaf
		if branches == 0:
			self.parse_leaf(node)
		node["child_list"] = []
		for i in xrange(branches):
			child_node = {}
			# length
			child_node["length"] = self.read_byte()
			# variant mask
			if child_node["length"] < 0x10:
				child_node["variant_mask"] = self.read_max_2_bytes()
			elif child_node["length"] <= 0x20:
				child_node["variant_mask"] = self.read_multiple_bytes()
			elif child_node["length"] <= 0x40:
				child_node["variant_mask"] = (self.read_multiple_bytes() << 32) + self.read_multiple_bytes()
			# pattern bytes
			child_node["variant_bool_array"] = []
			child_node["pattern_bytes"] = []
			current_mask_bit = 1 << (child_node["length"] - 1)
			for j in xrange(child_node["length"]):
				if child_node["variant_mask"] & current_mask_bit != 0:
					child_node["variant_bool_array"].append(True)
					child_node["pattern_bytes"].append(0x00)
				else:
					child_node["variant_bool_array"].append(False)
					child_node["pattern_bytes"].append(self.read_byte())
				current_mask_bit >>= 1
			self.parse_tree(child_node)
			node["child_list"].append(child_node)

	def parse_leaf(self, node):
		node["module_list"] = []
		while True:
			crc_length = self.read_byte()
			crc16 = self.read_short()
			while True:
				module = {}
				module["crc_length"] = crc_length
				module["crc16"] = crc16
				module["length"] = self.read_multiple_bytes() if self.header["version"] >= 9 else self.read_max_2_bytes()
				# public function
				module["public_functions"] = []
				offset = 0
				while True:
					public_function = {}
					offset += self.read_multiple_bytes() if self.header["version"] >= 9 else self.read_max_2_bytes()
					public_function["offset"] = offset
					current_byte = self.read_byte()
					if current_byte < 0x20:
						if current_byte & self.flag["function"]["LOCAL"]:
							public_function["is_local"] = True
						if current_byte & self.flag["function"]["UNRESOLVED_COLLISION"]:
							public_function["is_collision"] = True
						if current_byte & self.flag["function"]["NEGATIVE_OFFSET"]:
							public_function["offset"] *= -1
						# if bool(current_byte & 0x01) or bool(current_byte & 0x04):
						current_byte = self.read_byte()
					public_function["name"] = ""
					while current_byte >= 0x20:
						public_function["name"] += chr(current_byte)
						current_byte = self.read_byte()
					flags = current_byte
					module["public_functions"].append(public_function)
					if not flags & self.flag["parse"]["MORE_PUBLIC_NAMES"]:
						break
				# tail bytes
				if flags & self.flag["parse"]["READ_TAIL_BYTES"]:
					module["tail_bytes"] = []
					n_tail_bytes = self.read_byte() if self.header["version"] >= 8 else 1
					for i in xrange(n_tail_bytes):
						tail_bytes = {}
						tail_bytes["offset"] = self.read_multiple_bytes() if self.header["version"] >= 9 else self.read_max_2_bytes()
						tail_bytes["value"] = self.read_byte()
						module["tail_bytes"].append(tail_bytes)
				# referenced function
				if flags & self.flag["parse"]["READ_REFERENCED_FUNCTIONS"]:
					module["referenced_functions"] = []
					n_referenced_functions = self.read_byte() if self.header["version"] >= 8 else 1
					for i in xrange(n_referenced_functions):
						referenced_function = {}
						referenced_function["offset"] = self.read_multiple_bytes() if self.header["version"] >= 9 else self.read_max_2_bytes()
						name_length = self.read_byte()
						if name_length == 0:
							name_length = self.read_multiple_bytes()
						referenced_function["name"] = ""
						for j in xrange(name_length):
							referenced_function["name"] += chr(self.read_byte())
						if referenced_function["name"][name_length - 1] == 0:
							referenced_function["offset"] *= -1
						module["referenced_functions"].append(referenced_function)
					if len(module["referenced_functions"]) > 1:
						print module
						exit()
				node["module_list"].append(module)
				if not flags & self.flag["parse"]["MORE_MODULES_WITH_SAME_CRC"]:
					break
			if not flags & self.flag["parse"]["MORE_MODULES"]:
				break

	def dump_header(self):
		print "signature :", self.header["signature"],
		print "(%i modules)" % self.header["n_functions"] if self.header["version"] >= 6 else ""
		print "version :", self.header["version"]
		print "arch :", self.flag["arch"][str(self.header["arch"])], "(0x%X)" % self.header["arch"]
		print "file_types :",
		for file_type, fflag in self.flag["file_types"].iteritems():
			if fflag & self.header["file_types"]:
				print file_type,
		print "(0x%X)" % self.header["file_types"]
		print "os_types :",
		for os_type, fflag in self.flag["os_types"].iteritems():
			if fflag & self.header["os_types"]:
				print os_type,
		print "(0x%X)" % self.header["os_types"]
		print "app_types :",
		for app_type, fflag in self.flag["app_types"].iteritems():
			if fflag & self.header["app_types"]:
				print app_type,
		print "(0x%X)" % self.header["app_types"]
		print "features :",
		for feature, fflag in self.flag["features"].iteritems():
			if fflag & self.header["features"]:
				print feature,
		print "(0x%X)" % self.header["features"]