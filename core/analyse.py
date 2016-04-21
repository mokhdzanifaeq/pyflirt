from capstone import *
from capstone.x86 import *
from ctypes import c_ushort
from struct import unpack

class function:
    def __init__(self, binary, sections, tree):
        self.binary = binary
        self.sections = sections
        self.tree = tree
        self.count = 0
        self.functions = {}
        self.referenced_functions = {}
        self.get_functions()

    def get_functions(self):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.skipdata = True
        # search for function in each section
        for i, section in enumerate(self.sections):
            # check if section is executable
            if section.characteristics & 0x20000020:
                raw_section = self.binary[section.pointer_to_raw_data:section.pointer_to_raw_data + section.virtual_size]
                for insn in md.disasm(raw_section, 0):
                    # search for call instruction that point to relative address
                    if insn.mnemonic == "call" and insn.op_str[:2] == "0x":
                        address = int(insn.op_str, 0)
                        if not address in self.functions:
                            self.functions[address] = [i]
        if not self.functions:
            raise Exception("cannot find any function")
        # get functions name based on flirt signature
        for data in self.functions.items():
            for child_node in self.tree["child_list"]:
                if self.node_match(child_node, data, 0):
                    break
        # check for skipped referenced function
        while True:
            temp = self.referenced_functions
            for data in self.referenced_functions.items():
                for child_node in self.tree["child_list"]:
                    if self.node_match(child_node, data, 0):
                        break
            # stop if does not found any referenced function
            if not self.referenced_functions or temp == self.referenced_functions:
                break
        if not self.count:
            raise Exception("cannot find matched function")

    def node_match(self, node, data, offset):
        if self.pattern_match(node, data[0] + self.sections[data[1][0]].pointer_to_raw_data + offset):
            if node["child_list"]:
                for child_node in node["child_list"]:
                    if self.node_match(child_node, data, offset + node["length"]):
                        return True
            elif node["module_list"]:
                for module in node["module_list"]:
                    if self.module_match(module, data):
                        return True
        return False

    def pattern_match(self, node, offset):
        for i in xrange(node["length"]):
            if not node["variant_bool_array"][i]:
                if node["pattern_bytes"][i] != ord(self.binary[offset + i]):
                    return False
        return True

    def module_match(self, module, data):
        base = data[0] + self.sections[data[1][0]].pointer_to_raw_data
        # check crc
        if module["crc16"] != self.crc16(base + 32, module["crc_length"]):
            return False
        # check tail bytes
        for tail_byte in module.get("tail_bytes", []):
            if self.binary[base + 32 + module["crc_length"] + tail_byte["offset"]] != tail_byte["value"]:
                return False
        # check referenced function
        if "referenced_functions" in module:
            for ref_function in module["referenced_functions"]:
                # get addess for referenced function
                ref_offset = base + ref_function["offset"]
                call_opcode = ord(self.binary[ref_offset - 1])
                # relative or absolute call? still unsure if absolute is used
                if call_opcode == 0xe8:
                    ref_address = unpack("<i", self.binary[ref_offset:ref_offset + 4])[0] + ref_offset + 4
                elif call_opcode == 0xff:
                    ref_address = unpack("<i", self.binary[ref_offset:ref_offset + 4])[0]
                else:
                    return False
                ref_address -= self.sections[data[1][0]].pointer_to_raw_data
                # check if referenced function have name
                if len(self.functions[ref_address]) > 1:
                    if ref_function["name"] != self.functions[ref_address][1]:
                        return False
                else:
                    self.referenced_functions[data[0]] = self.functions[data[0]]
                    return False
            # passes referenced fuction checking, remove referenced function address from dictionary
            self.referenced_functions.poo(data[0], None)
        for public_function in module["public_functions"]:
            if public_function["name"] != "?":
                if public_function["offset"] == 0:
                    self.functions[data[0]].append(public_function["name"])
                else:
                    self.functions[data[0] + public_function["offset"]] = [data[1][0], public_function["name"]]
                self.count += 1
        return True

    # direct port from flair tools flair/crc16.cpp
    def crc16(self, base, length):
        if length == 0:
            return 0
        crc = 0xffff
        for i in xrange(length):
            data = ord(self.binary[base + i])
            for j in xrange(8):
                if (crc ^ data) & 1:
                    crc = (crc >> 1) ^ 0x8408
                else:
                    crc >>= 1
                data >>= 1
        crc = ~crc
        data = crc
        crc = (crc << 8) | ((data >> 8) & 0xff)
        return c_ushort(crc).value
