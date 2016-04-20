from os.path import dirname
from ctypes import *
import json
import datetime

class file_header(Structure):
    _fields_ =  [
        ("magic", c_char * 4),
        ("machine", c_ushort),
        ("number_of_sections", c_ushort),
        ("time_date_stamp", c_uint),
        ("pointer_to_symbol_table", c_uint),
        ("number_of_symbols", c_uint),
        ("size_of_optional_header", c_ushort),
        ("characteristics", c_ushort)
    ]

class optional_header(Structure):
    _fields_ =  [
        ("magic", c_ushort),
        ("major_linker_version", c_ubyte),
        ("minor_linker_version", c_ubyte),
        ("size_of_code", c_uint),
        ("size_of_initialized_data", c_uint),
        ("size_of_uninitialized_data", c_uint),
        ("address_of_entry_point", c_uint),
        ("base_of_code", c_uint),
        ("base_of_data", c_uint),
        ("image_base", c_uint),
        ("section_alignment", c_uint),
        ("file_alignment", c_uint),
        ("major_operating_system_version", c_ushort),
        ("minor_operating_system_version", c_ushort),
        ("major_image_version", c_ushort),
        ("minor_image_version", c_ushort),
        ("major_subsystem_version", c_ushort),
        ("minor_subsystem_version", c_ushort),
        ("win32Version_value", c_uint),
        ("size_of_image", c_uint),
        ("size_of_headers", c_uint),
        ("check_sum", c_uint),
        ("subsystem", c_ushort),
        ("dll_characteristics", c_ushort),
        ("size_of_stack_reserve", c_uint),
        ("size_of_stack_commit", c_uint),
        ("size_of_heap_reserve", c_uint),
        ("size_of_heap_commit", c_uint),
        ("loader_flags", c_uint),
        ("number_of_rva_and_sizes", c_uint)
    ]

class section_header(Structure):
    _fields_ =  [
        ("name", c_char * 8),
        ("virtual_size", c_uint),
        ("virtual_address", c_uint),
        ("size_of_raw_data", c_uint),
        ("pointer_to_raw_data", c_uint),
        ("pointer_to_relocations", c_uint),
        ("pointer_to_linenumbers", c_uint),
        ("number_of_relocations", c_ushort),
        ("number_of_linenumbers", c_ushort),
        ("characteristics", c_uint)
    ]

class pe:
	def __init__(self, binary, dump =  False):
		self.binary = binary
		# magic
		if self.binary[:2] != "MZ":
			raise Exception("binary is not supported")
		self.parse_pe_header()
		if dump:
			self.dump_pe_header()

	def parse_pe_header(self):
		# skip to PE offset
		skip = ord(self.binary[60:61])
		# parse file header
		self.header = file_header.from_buffer_copy(self.binary[skip:])
		skip += sizeof(file_header)
		if self.header.magic != "PE":
			raise Exception("bad PE signature")
		# parse optional file header
		self.opt_header = optional_header.from_buffer_copy(self.binary[skip:])
		skip += self.header.size_of_optional_header
		if self.header.machine != 0x014c or self.opt_header.magic != 0x10b:
			raise Exception("only intel x86 binary is supported")
		# parse sections
		self.sections = []
		for i in xrange(self.header.number_of_sections):
			section = section_header.from_buffer_copy(self.binary[skip:])
			skip += sizeof(section_header)
			self.sections.append(section)

	def dump_pe_header(self):
		with open(dirname(__file__) + "/flag/binary.json") as JSONdata:
		    flag = json.load(JSONdata)
		print "IMAGE_FILE_HEADER\n"
		for field_name, field_type in file_header._fields_:
			val = getattr(self.header, field_name)
			if field_name == "magic":
				print "magic :", val
			elif field_name == "machine":
				print "machine : x86"
			elif field_name == "time_date_stamp":
				print "time_date_stamp :", datetime.datetime.fromtimestamp(val).strftime('%d-%m-%Y %H:%M:%S')
			elif field_name == "characteristics":
				print "characteristics :",
				for characteristic, fflag in flag["characteristic"].iteritems():
					if fflag & val:
						print characteristic,
				print "(0x%X)" % val
			else:
				print field_name, ":", val
		print "\nOPTIONAL_FILE_HEADER\n"
		for field_name, field_type in optional_header._fields_:
			val = getattr(self.opt_header, field_name)
			if field_name == "subsystem":
				print "subsystem :", flag["subsystem"][str(val)]
			elif field_name == "address_of_entry_point" or field_name[:7] == "base_of":
				for section in self.sections:
					if val >= section.virtual_address and val <= section.virtual_address + section.virtual_size:
						print field_name, ": %d (%s)" % (val, section.name)
						break
			elif field_name == "dll_characteristics":
				print "dll_characteristics :",
				for dll_characteristic, fflag in flag["dll_characteristic"].iteritems():
					if fflag & val:
						print dll_characteristic,
				print "(0x%X)" % val
			else:
				print field_name, ":", val
		print "\nSECTION_HEADER"
		for section in self.sections:
			print ""
			for field_name, field_type in section_header._fields_:
				val = getattr(section, field_name)
				if field_name == "characteristics":
					print "characteristics :",
					for characteristic, fflag in flag["section_characteristic"].iteritems():
						if fflag & val:
							print characteristic,
					print "(0x%X)" % val
				else:
					print field_name, ":", val
