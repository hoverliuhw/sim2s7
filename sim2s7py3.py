#!/usr/bin/env python3

# sim2s7py3.py is python3 version of sim2s7.py, mainly difference is bytes operation

# sim2s7.py is to run an ss7 state machine(similar to mgts), which is defined in a json file
# function simulates /cs/sn/utest/s7sch/sim2s7, http://inu.ih.lucent.com/~ss7team/sim2s7/QIP.html
# this script can be run on any host, including local mcas pilot
# softshelf version s7sch is used on mcas, same as mgts softself

# usage: sim2s7py3.py --mcas_host=<mcas pilot floating ip> --state=<state machine json file> [--timeout=<failure timeout>]
#           -h, -m, --mcas_host     pilot ip of mcas host
#           -s, --state             state macine json file
#           -t, --timeout           global failure timeout when response is no received
#           --help                  usage
#    example:   ./sim2s7py3.py --mcas_host=135.242.107.153 --state=vfq_cml_og_v3.json
#               ./sim2s7py3.py -h 135.242.107.153  -s vfq_cml_og_v3.json
#    note: if run on local host, the ip is also the real mcas_host ip, 127.0.0.1 does not work

# Liu Hongwei
# 2021.05.15    created
# 2021.05.19    update to v3, to support different types in databases, such as decimal, phonenumber, and hex
#               also support import source entity for point code
#               this update is to support state machine json files converted from mgts .states file5.
# 2021.05.21    enhanced v3 import database fields part
# 2021.06.21    enhanced to support of import "text" type in database
# 2021.08.10    migrate to python3 version
# 2021.09.17    add support for ANSI-SS7
# 2022.01.12    fix bug of higher bit value loss in cp2msg
# 2022.02.22    fix bug of database value length is shorter than message template field length
#               previous behavior is append 0s, while MGTS will keep bytes in message template
#               fix that to behave the same as MGTS

import socket
import time
import json
import sys
import getopt
import struct

version = 3.0

class StateMachine():
    defaulttimeout = 30

    # the entity is to simulate network map on mgts, for importing point code
    # currently, we only support itu
    # for itu, it is 2 bytes(3-8-3), 14bits at MTP layer, 16bits at SCCP layer
    # e.g. scp point code: 0-38-5
    #       bin: 000 00100110 101, hex: 0x135, dec: 0*2048 + 38*8 + 5 = 309
    #      ssp point code: 0-25-1
    #       bin: 000 00011001 001, hex: 0xc9, dec: 0*2048 + 25*8 + 1 = 201
    # but for ansi, it is 3 bytes(8-8-8)
    entities = {
        # ITU: SCP: 0x135(0-38-5), SSP: 0xC9(0-25-1) 
        "CCITT-SS7": {"1": "0-38-5", "2": "0-25-1"},
        # ANSI: SCP: 0xe61e0d(230-30-13), SSP: 0xe60100(230-1-0)
        "ANSI-SS7": {"1": "230-30-13", "2": "230-1-0", "3": "0xe61e0e"}
        }
    sigstd = "CCITT-SS7"
    entity = entities[sigstd]

    @classmethod
    def settimeout(cls, timeout):
        cls.defaulttimeout = timeout
    @classmethod
    def setsigstd(cls, sigstd):
        cls.sigstd = sigstd
        cls.entity = cls.entities[cls.sigstd]

    def __init__(self):
        # refer pcap trace, passThru uses udp port 7555
        self.port = 7555

        # default timeout is 30s, if state machine doesn't receive message within this time, it will stop
        self.timeout = StateMachine.defaulttimeout
        self.abort = False
        
        # on mgts, cdr_buffer is an array, length is 0-99
        # here we use dict, for convention, digit str is used as key
        self.cdr_buffer = dict()

        # database is to simulate .pdb file on mgts
        self.database = None
        # list of states of state machine
        self.states = None

    def connect(self, mcas_host):
        self.mcas_addr = (mcas_host, self.port)
        self.s7_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def disconnect(self):
        self.s7_socket.close()
    
    def loadstate(self, JSONObj):
        # load state machine from a json object, which is read from a json file
        # a state machine file consists of three parts: sigstd, database and states list
        StateMachine.setsigstd(JSONObj.get("sigstd", "CCITT-SS7"))
        self.database = JSONObj.get("database", {})
        self.states = JSONObj.get("states", [])
    
    @staticmethod
    def cp2msg(val, msg_template, pos, width):
        # val and msg_template are raw str, eg. "83".decode("hex")
        # pos and width are all in bits
        # need put reverse here? or outside cp2msg(), now it is outside of cp2msg
        # the lower byte in the first byte of messege

        v = int(val.hex(), 16)
        total_mask = (1<<width) - 1 # incase longer val than width
        v = v & total_mask
        div = pos // 8
        mod = pos % 8

        # keep the lower bits of current byte, it belongs to previous field
        # if width < 8, also keep the higher bits of current byte
        res = bytes()
        msg_cur = msg_template[div]
        # fix bug: if width is less than one byte, left bits will be lost
        # before fix: mask = (1 << mod) -1
        mask = 0xff ^ ((0xff & total_mask) << mod)
        msg_cur = msg_cur & mask
        # get the rest (8-mod) bits from val
        mask = (0xff ^ mask) >> mod
        bits = (v & mask) << mod
        # combine
        msg_cur = msg_cur | bits
        # change it to str, if print, using .decode("hex")
        s = struct.pack(">i", msg_cur)[-1].to_bytes(1, "big")
        res = res + s

        # process the middle part
        v = v >> (8 - mod)
        width = width - (8 - mod)
        if width < 0: # some field is shorter than 1 byte
            width = 0
        div = width // 8
        mod = width % 8
        mask = 0xff
        for i in range(div):
            s = struct.pack(">i", v & mask)[-1].to_bytes(1, "big")
            res = res + s
            v = v >> 8
        
        # if pos is the last byte
        if (pos // 8 + div + 1) >= len(msg_template):
            return msg_template[ : pos//8] + res

        # process the left bits
        msg_cur = msg_template[pos // 8 + div + 1]
        mask = (1 << mod) -1
        v = v & mask # need this in case higher part has value 
        mask = ~mask # or (0xff ^ mask)
        msg_cur = msg_cur & mask # higher part, left bits is lower part
        msg_cur = msg_cur | v 
        s = struct.pack(">i", msg_cur)[-1].to_bytes(1, "big")

        res = res + s
        msg_template = msg_template[ : pos//8] + res + msg_template[pos//8 + 1 + div + 1 : ]

        return msg_template

    def pre_import(self):
        # load import fields that are from database/entity before running
        # this is to avoid unnecessary delay due to process imports
        print("\nLOAD:\t---------------------    PreLoad Data    ---------------------")
        bitmark = 10000
        for state in self.states:
            state_type = state.get("type")
            if state_type != "tx":
                continue

            print("\nLOAD:\t{0}".format(state.get("name")))
            
            import_list = state.get("imports", [])
            for item in import_list:
                import_src = item.get("source")
                if import_src == "cdr_buffer":
                    # cdr_buffer is import at run-time
                    continue

                import_name = item.get("name")
                src_field = item.get("src_field")
                pos = item.get("pos")
                import_len = item.get("length")

                import_val = None
                printable_val = import_val # for print info, may delete in the future
                # msg_template = bytes.fromhex(state.get("msg_template"))
                if import_src == "database":
                    # field in database structure is changed to a dict
                    # a field contains type and value
                    # in mgts system, there are 5 types used:
                    #       Decimal, Hex, PhoneNumber, PointCode(e.g. 0-38-5), Text
                    #   we changed these type to lower case:
                    #       decimal, hex, phonenumber, pointcode(e.g. 0-38-5), text
                    import_field = self.database.get(src_field, None)
                    if import_field == None:
                        continue
                    field_type = import_field["type"]
                    import_val = import_field["value"]
                    if field_type == "phonenumber":
                        printable_val = import_val
                        import_val = import_val + "0" * (len(import_val) % 2)
                        if import_len < bitmark and len(import_val) < import_len * 2:
                            # to fix problem that SPID-1051/SPTMS-11068.json met
                            # if val/database length < target length, will append 0s in function cp2msg()
                            #   this is different from mgts, mgts will keep the bytes in message template, 
                            #   while we use 0s to replace
                            #   from 2022.02.22, we fix, to do the same as mgts by changing import_len
                            #   for phonenumber type, we need keep looking whether it is correct to do so
                            #       because phonenumber is used by address, or ivr return digits
                            import_len = len(import_val) // 2
                        import_val = bytes.fromhex(import_val[ : : -1])
                    elif field_type == "hex":
                        # make sure import_val's length is even value, if it is odd, insert 0 before import_val
                        # this is unnecessary if <state>.json is converted from state2j, put it here in case <state>.json is edited manually
                        import_val = (len(import_val) % 2) * "0" + import_val
                        # in case import_len is not integral of bytes
                        # so here we used import_bytes
                        import_bytes = import_len
                        if import_bytes > bitmark:
                            import_bytes = (import_bytes // bitmark) // 8 + 1
                        else:
                            # to solve shorter value length than template length
                            # we only handle scenario that import_len is integral value of bytes
                            if len(import_val) < import_bytes * 2:
                                # if val length < database length, will insert 0s, 
                                #   this is done in state2j when loading database
                                # if val/database length < target length, will append 0s
                                #   this is different from mgts, mgts will keep the bytes in message template, 
                                #   while we use 0s to replace
                                #   from 2022.02.22, we fix, to do the same as mgts by changing import_len
                                import_len = len(import_val) // 2

                        # if len(import_val) < import_bytes * 2:
                            # import_val = import_val + "0" * (import_bytes * 2 - len(import_val))
                            
                        printable_val = import_val
                        import_val = bytes.fromhex(import_val)[ : : -1]
                    elif field_type == "decimal":
                        printable_val = import_val
                        dec = int(import_val)
                        import_val = hex(dec)[2 : ]
                        import_val = "0" * (len(import_val) % 2) + import_val
                        # from the test of nokia og acr time, copied from decimal field
                        # lower byte should be in the first, so not reverse before cp2msg
                        import_val = bytes.fromhex(import_val)
                    elif field_type == "pointcode":
                        # return value of process point code is int
                        pc = self.process_pointcode(import_val)
                        import_val = hex(pc)[2 : ]
                        import_val = "0" * (len(import_val) % 2) + import_val
                        printable_val = import_val
                        import_val = bytes.fromhex(import_val)
                    elif field_type == "text":
                        # text might be used in pac result
                        # character is converted to ascii value, then hex, then copy to message
                        # assume length is integral of bytes
                        ascii_str = ""
                        for c in import_val:
                            ascii_str = ascii_str + hex(ord(c))[2 : ]
                        printable_val = ascii_str
                        import_val = bytes.fromhex(ascii_str)[ : : -1]
                    else:
                        # other types will be skipped
                        continue
                    
                elif import_src == "entity":
                    # repeat process pointcode part
                    pc = self.process_pointcode(StateMachine.entity[src_field])
                    import_val = hex(pc)[2 : ]
                    import_val = "0" * (len(import_val) % 2) + import_val
                    printable_val = import_val # for print info
                    import_val = bytes.fromhex(import_val)
                else:
                    continue

                msg_template = bytes.fromhex(state.get("msg_template"))
                # convert length and pos to bits
                width = import_len // bitmark if import_len > bitmark else (import_len * 8)
                pos = pos // bitmark if pos > bitmark else (pos * 8)

                msg = self.cp2msg(import_val, msg_template, pos, width)
                print("\tImport {0}: {1} from {2} {3}".format(import_name, printable_val, import_src, src_field))                
                state["msg_template"] = msg.hex()

    def process_pointcode(self, val):
        if StateMachine.sigstd == "CCITT-SS7":
            segs = val.split("-")
            # ITU Point Code format is 3bits - 8bits - 3bits
            return (int(segs[0]) << 11) + (int(segs[1]) << 3) + int(segs[2])
        elif StateMachine.sigstd == "ANSI-SS7":
            segs = val.split("-")
            # ANSI Point Code format is 8bits - 8bits - 8bits
            return (int(segs[0]) << 16) + (int(segs[1]) << 8) + int(segs[2])
        else:
            pass
        return None
   
    def run(self):
        # run all of states in state machine
        if not self.states:
            print("State machine is empty")
            return

        self.pre_import() # load import fields that are from database/entity,

        print("\nSTART:\t--------------------- Start State Machine ---------------------")
        for state in self.states:
            if self.abort:
                self.abort = False
                break

            state_name = state.get("name")
            state_type = state.get("type")

            # currently, only 3 types defined: tx, rx, timer
            if state_type == "timer":
                # the duration in state machine file is in millisecond
                dura = float(state.get("duration")) / 1000
                print("\nTIMER:\tWait for {0} seconds".format(dura))
                time.sleep(dura)

            elif state_type == "tx":
                print("\nSEND:\t{0}".format(state_name))
                self.send(state)

            elif state_type == "rx":
                print("\nRECV:\t{0}".format(state_name))
                self.recv(state)

            else:
                # in case other types are read
                pass
        print("\nSTOP:\t--------------------- Stop State Machine ---------------------\n")

    def send(self, state):
        msg = bytes.fromhex(state.get("msg_template"))
        # process import, in send state, no export
        # at run time, only process imports from cdr_buffer
        # for other import sources like database/entity, they are processed in pre_import() before running state machine

        # currently we only support im/ex port transaction id from/to cdr buffer
        #   and assume: pos % 8 ==0; length % 8 == 0
        # this can meet most scenarios, but not enough, e.g. correlation id in ETC/ARI
        import_list = state.get("imports", [])
        for item in import_list:
            import_src = item.get("source")

            if not import_src == "cdr_buffer":
                # only import cdr_buffer at run time
                continue

            import_name = item.get("name")
            src_field = item.get("src_field")
            pos = item.get("pos")
            import_len = item.get("length")

            import_val = self.cdr_buffer.get(src_field, None)
            if import_val == None:
                continue

            # acturally for cdr buffer, no need to compare length
            # put here for logical integrity
            # and we assume length is in times of bytes
            src_length = len(import_val)
            if src_length > import_len:
                import_val = import_val[ : import_len]
            elif src_length < import_len:
                # according to database type
                import_len = src_length
            else:
                import_len = src_length
            
            print("\tImport {0}: {1} from {2}".format(import_name, import_val.hex(), import_src))                
            msg = msg[ : pos] + import_val + msg[pos + import_len : ]
            
        self.s7_socket.sendto(msg, self.mcas_addr)
        print("\tSent message to {0}, length is {1}".format(self.mcas_addr, len(msg)))

    def recv(self, state, read_buf = 1024):
        # currently there is no state level timeout in state machine file
        # if it is added, it is in second, e.g. 5 means 5s
        timeout = state.get("timeout", self.timeout)
        if not timeout > 0:
            # in case the timeout in state is 0
            # we also assume the fail timer in mgts state machine is in seconds
            # not millisecond
            timeout = self.timeout
        self.s7_socket.settimeout(timeout)
        try:
            recv_data, address = self.s7_socket.recvfrom(read_buf)
            print("\tReceived message from {0}, length is {1}".format(address, len(recv_data)))

            # process exports, in recv state, not imports
            # and now, exports only supports cdr_buffer, which is enough
            # we also assume all fields length is integral of bytes, not bits
            export_list = state.get("exports", [])
            for item in export_list:
                export_name = item.get("name")
                export_dest = item.get("dest")
                export_len = item.get("length")
                pos = item.get("pos")
                dest_field = item.get("dest_field")

                # default is all 0x00, for python 3, decode() is bytes.fromhex()
                # if cdr_buffer has value, use it as default, if not, use all 0x00
                export_val = self.cdr_buffer.get(dest_field, bytes.fromhex("00") * export_len)
                if pos > 0 and len(recv_data) >= pos + export_len:
                    export_val = recv_data[pos : pos + export_len]
                # the value exported is raw data, no encode/decode
                self.cdr_buffer[dest_field] = export_val
                print("\tExport {0}: {1} to cdr_buffer field {2}".format(export_name, export_val.hex(), dest_field))
        except socket.timeout:
            print("ERRO:\tNo message received, timeout after waiting for {0} seconds".format(timeout))
            self.abort = True

def usage():
    print(''' 
    usage: sim2s7py3.py --mcas_host=<mcas pilot floating ip> --state=<state machine json file> [--timeout=<failure timeout>]
            -h, -m, --mcas_host     pilot ip of mcas host
            -s, --state             state macine json file
            -t, --timeout           global failure timeout when response is no received
            --help                  usage
     example:   ./sim2s7py3.py --mcas_host=135.242.107.153 --state=vfq_cml_og_v3.json
                ./sim2s7py3.py -h 135.242.107.153  -s vfq_cml_og_v3.json
     note: if run on local host, the ip is also the real mcas_host ip, 127.0.0.1 does not work ''')
    sys.exit(1)

if __name__ == '__main__':
    state_machine_file = None
    mcas_host = None

    if len(sys.argv) == 1:
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:m:s:t:", ["help", "mcas_host=", "state=", "timeout="])
    except getopt.GetoptError as e:
        print(e)
        usage()

    for opt, value in opts:
        if opt in ("-h", "-m", "--mcas_host"):
            mcas_host = value
        if opt in ("-s", "--state"):
            state_machine_file = value
        if opt in ("-t", "--timeout"):
            defaulttimeout = int(value)
            if defaulttimeout > 0:
                StateMachine.settimeout(defaulttimeout)
        if opt == "--help":
            usage()
    if mcas_host == None or state_machine_file == None:
        print("ERROR: no mcas host or state machine file specified")
        usage()

    # read state machine from json file
    f = open(state_machine_file, "r")
    state_json_obj = json.load(f)
    f.close()

    # load state machine and run
    state_machine = StateMachine()
    state_machine.connect(mcas_host)
    state_machine.loadstate(state_json_obj)
    
    state_machine.run()

    state_machine.disconnect()