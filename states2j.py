#!/usr/bin/env python3
# this is a python 2/3 script to convert mgts .states file to json file
# which can be used by sim2s7.py
#
# Liu Hongwei
# 2021.05.19    created
# 2021.05.22    finished
# 2021.09.17    add sigstd in <state>.json file to support ANSI-SS7,
#               and remove sigstd in arguments, because this parameter will be read from .states file
# 2023.01.30    use FLAVOR to search .udm and .layer files, not SIGSTD any more, because this not work for FREEFMT
#               this bug is found by Zhang Xueyuan

import json
import sys
import os
import getopt

class State():
    # or Node, we use state here because it composes state machine
    # id: node id
    # name: name of node
    # type: normal, start, stop, pass/fail, timeout, others are comment/action/decision
    # direction: only for normal
    # message_template: tx or rx template, it is message template name, 
    # msg_raw: tx or rx message raw data, only meaningful for tx, it will be sent to ocs
    # import_list: list of import fields, need define a field
    # export_list: list of export fields, need define a field
    # specific_attr: timer's duration, pass/fail's status
    # children: next states after this state(node), maybe multiple, so it is a list
    def __init__(self, nodeid):
        self.nodeid = nodeid
        self.direction = None
        self.msg_template = None
        self.msg_raw = ""
        self.base_offset = 0 # in case mgts message template has TEKPRIM TEKLSL layer, need skip 10bytes, e.g. vfhu ft1309
        self.import_list = []
        self.export_list = []
        # special_attr is some uniq attributes for special node type, 
        #   for timer, its value is timer(in milliseconds)
        #   for pass or fail node, it is pass or fail state
        self.special_attr = None
        self.children = []
        # failure timeout, only meaningful for rx node, unit is second
        self.timeout = 0
        # flavor, help to find the udm message under SigStd
        self.flavor = StateMachine.sigstd
    #def __str__(self):
    #    return "{0}_{1}_{2}".format(self.nodeid, self.name, self.node_type)
    def set_name(self, name):
        self.name = name
    def set_type(self, node_type):
        self.node_type = node_type
    def set_direction(self, direction):
        self.direction = direction
    def set_template(self, template):
        self.msg_template = template
    def add_import(self, item):
        self.import_list.append(item)
    def add_export(self, item):
        self.export_list.append(item)
    def set_special(self, attr):
        self.special_attr = attr
    def add_child(self, child_nodeid):
        self.children.append(child_nodeid)
    def set_timeout(self, timeout):
        self.timeout = timeout
    def set_flavor(self, flavor):
        self.flavor = flavor

    def load_raw_msg(self):
        # convert message template into raw message
        # thru reading layer files in <message template>.udm file
        if not self.node_type == "normal":
            return
        datafiles = StateMachine.datafiles
        sigstd = StateMachine.sigstd

        ft_udm = open(os.path.sep.join((datafiles, "SigStd", self.flavor, self.msg_template + ".udm")), "r")
        layer_list = []
        for line in ft_udm.readlines():
            line = line.strip()
            start = 9 # line starts with "PROTOCOL="
            end = line.find(" ", start)
            protocol = line[start : end]

            if protocol in ("TEKPRIM", "TEKLSL"):
                # "TEKPRIM" and "TEKLSL" count 10bytes when calculate import/export position
                # "TEKPRIM" counts 3 bytes, "TEKLSL" counts 7 bytes
                # but in sent/recv message, they are not included because they are used by mgts internally
                self.base_offset = 80
                continue

            start = line.find("LAYER", end) + 6
            layer = line[start : ]
            layer_list.append(os.path.sep.join((protocol, layer)))
        ft_udm.close()
        msg_raw = ""
        for layer in layer_list:
            ft_layer = open(os.path.sep.join((datafiles, "SigStd", self.flavor, layer)), "r")
            line = ft_layer.readline()
            raw_found = False
            for line in ft_layer.readlines():
                line = line.strip()
                if raw_found:
                    if line.endswith(">"):
                        msg_raw = msg_raw + line[: -1]
                        raw_found = False
                    else:
                        msg_raw = msg_raw + line
                if line.startswith("<"):
                    raw_found = True
                    if line.endswith(">"):
                        msg_raw = msg_raw + line[1 : -1]
                        raw_found = False
                    else:
                        msg_raw = msg_raw + line[1 : ]
            ft_layer.close()
        self.msg_raw = msg_raw.replace(" ","")

    def load_im_export_msg(self):
        # update import/export list, 
        # add the field's position and length(offset)
        # if the position/length is within 1 byte, time it by bitmark = 10000

        # only for tx/rx node
        if not self.node_type == "normal":
            return
        datafiles = StateMachine.datafiles
        sigstd = StateMachine.sigstd
        bitmark = 10000
        port_list = self.import_list if self.direction == "tx" else self.export_list

        # get layer list from all import/export fields, then read all files in one time
        # layer is like MTP, SCCP, MAP_Phase2 etc.
        layer_list = set()
        for field in port_list:
            layer_list.add(field["layer"])
        
        # read all of the importable/exportable fields of the message templates
        # store them in full_layer_fields
        full_layer_fields = dict()
        for layer in layer_list:
            full_layer_fields[layer] = dict()
            f = open(os.path.sep.join((datafiles, "SigStd", self.flavor, layer, self.msg_template + ".layer")), "r")
            for line in f.readlines():
                line = line.strip()
                if line.startswith("TRAP="):
                    # read field from layer file, this part can be moved to a static function in the future
                    start = 5
                    end = line.find(" ", start)
                    mnem = line[start : end]
                    field = dict()
                    # we may need add "ENCODING=" to indicate this field's format in layer file, 
                    # maybe useful when import, some layer file does not have ENCODING, eg.VFCZ/fs6844
                    # after testing, encoding is not necessary

                    # find the length of this field
                    start = line.find("LENGTH") + 7
                    end = line.find(" ", start)
                    length = int(line[start : end].split(",")[-1])
                    if length % 8 == 0:
                        length = int(length / 8)
                    else:
                        # for point code length less than 1 byte, 
                        # time it by bitmark(10000) to mark it, for future process
                        length = int(length * bitmark)
                    field["length"] = int(length)

                    start = line.find("OFFSET", end) + 7
                    end = line.find(" ", start)
                    pos = int(line[start : end]) - self.base_offset # in case message has "TEKPRIM" or "TEKLSL" layer
                    if pos % 8 == 0:
                        pos = int(pos / 8)
                    else:
                        # if position is in middle of a byte, 
                        # time it by bitmark(10000) to mark it, for future process
                        pos = int(pos * bitmark)
                    field["pos"] = pos
                    full_layer_fields[layer][mnem] = field
            f.close()

        # update import/export list by reading from full_layer_fields
        for field in port_list:
            mnem = field["mnem"]
            layer = field["layer"]
            field["pos"] = full_layer_fields[layer][mnem]["pos"]
            field["length"] = full_layer_fields[layer][mnem]["length"]
            # remove mnem and layer because they are not useful anymore
            field.pop("mnem")
            field.pop("layer")

    def to_json_obj(self):
        # return a complex dict that can be dumped by json, and printed
        obj = dict()
        obj["name"] = self.name
        if self.node_type == "normal":
            obj["type"] = self.direction
            obj["imports"] = self.import_list
            obj["exports"] = self.export_list
            # obj["msg_template"] = self.msg_template # will change to msg_raw
            obj["msg_template"] = self.msg_raw
            if self.direction == "rx" and self.timeout > 0:
                obj["timeout"] = self.timeout
        if self.node_type == "timeout":
            obj["type"] = "timer"
            obj["duration"] = self.special_attr
        
        return obj
        #return json.dumps(obj, sort_keys=False, indent=4, separators=(',', ': '))

    @staticmethod
    def gen_state(line):
        # this line must be the one in .states file, and starts with "NODEID="
        # get nid, type, name
        if not line.startswith("NODEID="):
            return None
        array = line.split()
        # get node id:
        nodeid = array[0].replace("NODEID=", "")
        state = State(nodeid)
        # get type
        node_type = array[1].replace("TYPE=", "")
        state.set_type(node_type)
        # get name
        start = line.find("NAME=") + 5 # because some name has space
        #name = array[-1].replace("NAME=", "")
        name = line[start : ]
        state.set_name(name)
        return state

    @staticmethod
    def gen_import_field(line):
        # this is to get import field of the sate in .states file
        # first 6 characters are "PARAM="
        if not line.startswith("PARAM="):
            return None
        field = dict()
        start = 6
        end = line.find("MNEM")
        name = line[start : end - 1]
        field["name"] = name
        # 5 means skip "MNEM="
        start = end + 5
        end = line.find(" ", start)
        mnem = line[start : end]
        field["mnem"] = mnem
        # got layer
        start = line.find("LAYER", end) + 6
        end = line.find(" ", start)
        layer = line[start : end]
        if layer.find("/") > 0:
            layer = layer[ : layer.find("/")]
        field["layer"] = layer
        # got source, support Entity, DataCell, CDRBuffer
        start = line.find("SOURCE=", end) + 7
        end = line.find(" ", start)
        source = line[start : end]
        
        if source == "CDRBuffer":
            source = "cdr_buffer"
            start = line.find("CDRBUFFER", end) + 10               
        elif source == "DataCell":
            source = "database"
            start = line.find("DB_COLUMN", end)  + 10
        elif source == "Entity":
            source = "entity"
            start = line.find("ENTITY", end) + 7
        else:
            # default is cdrbuffer's source field, but we wont handle that when running
            start = line.find("CDRBUFFER", end) + 10
        end = line.find(" ", start)
        src_field = line[start : end]
        field["source"] = source
        field["src_field"] = src_field

        return field

    @staticmethod
    def gen_export_field(line):
        # this is to get export field of the sate in .states file
        # first 6 characters are "PARAM=", PARAM refers to this fields name, different from .layer file
        field = dict()
        start = 6
        end = line.find("MNEM")
        name = line[start : end - 1]
        field["name"] = name
        # 5 means skip "MNEM="
        start = end + 5
        end = line.find(" ", start)
        mnem = line[start : end]
        field["mnem"] = mnem
        # got layer
        start = line.find("LAYER", end) + 6
        end = line.find(" ", start)
        layer = line[start : end]
        if layer.find("/") > 0:
            layer = layer[ : layer.find("/")]
        field["layer"] = layer
        # got destination, only support CDRBuffer
        start = line.find("DESTINATION", end) + 12
        end = line.find(" ", start)
        dest = line[start: end]
        if dest == "CDRBuffer":
            dest = "cdr_buffer"
        start = line.find("CDRBUFFER", end) + 10
        end = line.find(" ", start)
        dest_field = line[start : end]
        field["dest"] = dest
        field["dest_field"] = dest_field

        return field

class StateMachine():
    datafiles = "E:\\sim2s7\\mgts_state_machine"
    sigstd = "CCITT-SS7"
    @classmethod
    def set_datafiles(cls, datafiles_dir):
        cls.datafiles = datafiles_dir
    @classmethod
    def set_sigstd(cls, sigstd):
        cls.sigstd = sigstd
    # database, one database field contains name, format/type, length, value
    # states, this is all of states with detail information, including those not used in the file
    # state_machine # this is node id list that composes state machine
    def __init__(self):
        self.states = dict()
        self.state_machine = []
        self.database_name = None
        self.database = dict()
        
        # for finding state machine in all of states
        self.start_nodeid = None
        self.pass_nodeid = None
        self.fail_nodeid = None

        # for timeout of state machine failure
        self.global_timer_nodeid = None

        # only for searching state machine nodes in all of the states
        self.arrived_pass_node = False
        self.globalcounter = 0

    def set_states(self, states):
        self.states = states
    def set_state_machine(self, state_machine):
        self.state_machine = state_machine
    def set_database(self, database):
        self.database_name = database
    def load_database(self):
        if self.database_name == None:
            return
        database_file = StateMachine.datafiles + os.path.sep + self.database_name + ".pdb"
        fields = dict()
        f = open(database_file, "r")
        line = f.readline()
        is_getting_val = False
        field = None
        colname = None
        while line:
            # testing result on mgts gui shows column name is unique, and without space
            line = line.strip()
            if line.startswith("COLUMN"):
                field = dict()
                is_getting_val = True
                start = 7 # skip "COLUMN="
                end = line.find(" ", start)
                colname = line[start : end]

                # get width for adding 0s
                start = line.find("WIDTH=", end) + 6 # skip "WIDTH="
                end = line.find(" ", start)
                width = int(line[start : end])
                field["width"] = width

                start = line.find("TYPE=", end) + 5 # skip "TYPE="
                end = line.find(" ", start)
                ty = line[start : end].lower() # using lower case in future json file
                field["type"]  = ty
            elif is_getting_val and line.startswith("VALUE"):
                start = 6 # skip "VALUE="
                val = line[start :]
                # add 0s according length
                width = field["width"]
                ty = field["type"]
                if ty == "hex":
                    val = "0" * (2 * width - len(val)) + val
                if ty == "phonenumber":
                    val = val + "0" * (width - len(val))
                field.pop("width")
                field["value"] = val
                self.database[colname] = field
                is_getting_val = False
            else:
                pass
            line = f.readline()
        f.close()
    def filter_database(self):
        # this is used to delete those unused fields in database
        # the function is realized in state_machine_obj function using an arg
        pass

    def load_messages(self):
        # load raw messages and update import/export list with position and length
        for node_id in self.state_machine:
            state = self.states[node_id]
            state.load_raw_msg()
            state.load_im_export_msg()
    def set_timeout(self):
        for node_id in self.state_machine:
            state = self.states[node_id]
            if self.global_timer_nodeid == None:
                # in the recurision of finding state machine
                # the fail node may not be reached
                return
            failure_timer_state = self.states[self.global_timer_nodeid]
            failure_timer = failure_timer_state.special_attr
            # during processing states, all timer values are changed to milliseconds
            # we assume failure timer before "fail" node is bigger than 1s
            if type(failure_timer) != int:
                return
            failure_timer = int(failure_timer / 1000)
            if failure_timer and failure_timer > 0:
                state.set_timeout(failure_timer)
    
    def load(self, state_file):
        f = open(state_file, 'r')
        in_node = False
        state = None
        line = f.readline()
        while line:
            line = line.strip()
            if len(line) == 0:
                in_node = False
            
            # find SIGSTD
            if line.startswith("SIGSTD="):
                start = 7 # length of "SIGSTD="
                end = line.find(" ", start)
                sigstd = line[start : end]
                StateMachine.set_sigstd(sigstd)

            # find database name
            if line.find('DATABASE=') > 0:
                self.database_name = line.split()[1].replace('DATABASE=', '')
                if self.database_name == "<none>":
                    self.database_name = None

            if line.startswith("NODEID="):
                in_node = True
                # a state that only has nid, type, name
                state = State.gen_state(line)
                # add to states pool
                nodeid = state.nodeid
                self.states[nodeid] = state

                if state.node_type == "start":
                    self.start_nodeid = nodeid
            
            if in_node == True:
                node_type = state.node_type
                if node_type == "timeout":
                    line = f.readline().strip()
                    val = 0
                    if line.endswith("ms"):
                        val = int(line[6 : -2])
                    else:
                        val = int(line[6 : -1]) * 1000
                    state.set_special(val)
                if node_type == "pass/fail":
                    line = f.readline().strip()
                    result = line[-1]
                    if result == "T":
                        self.pass_nodeid = state.nodeid
                    else:
                        self.fail_nodeid = state.nodeid
                    state.set_special(result)
                if node_type == "normal":
                    if line.startswith("RXMSG"):
                        array = line.split()
                        rx = array[0].replace("RXMSG=", "")
                        tx = array[1].replace("TXMSG=", "")
                        if not rx == "<none>":
                            state.set_direction("rx")
                            state.set_template(rx)
                        else:
                            state.set_direction("tx")
                            state.set_template(tx)
                    if line.startswith("PARAM"):
                        direction = state.direction
                        if direction == "tx":
                            line = line + " " + f.readline().strip()
                            field = State.gen_import_field(line)
                            state.add_import(field)
                        if direction == "rx":
                            line = line + " " + f.readline().strip() + " " + f.readline().strip()
                            field = State.gen_export_field(line)
                            state.add_export(field)
                    if line.startswith("FLAVOR"):
                        array = line.split()
                        flavor = array[0].replace("FLAVOR=", "")
                        state.set_flavor(flavor)
                if node_type == "comment":
                    line = f.readline().strip()
                    num_of_line = int(line.split("=")[-1])
                    if num_of_line == 0:
                        state.special_attr = "No comments"
                    else:
                        s = ""
                        for i in range(num_of_line):
                            line = f.readline().strip()
                            s = s + line + "\n"
                        state.special_attr = s
                if node_type == "action":
                    state.special_attr = "Some actions, ignored"
                if node_type == "decision":
                    line = f.readline().strip()
                    state.special_attr = line.replace("DECISION=", "")
            if line.startswith("CONNID"):
                start = 7 # skip "CONNID="
                end = line.find(" ", start)
                nodeid = line[start : end]
                start = line.rfind("=") + 1
                children_s = line[start : ]
                children = children_s.split(",")
                if len(children_s) == 0:
                    children = []
                state = self.states[nodeid]
                for child in children:
                    state.add_child(child)
            line = f.readline()

        f.close()
        # generate the state machine
        self.state_machine.append(self.start_nodeid)
        self.search_end(self.start_nodeid)
        # load database fields
        self.load_database()
        self.load_messages()
        self.set_timeout()

    def search_end(self, start_nodeid):
        # to generate the state machine, this is a recursive function
        # using a globalcounter to avoid stack overflow in recursion
        self.globalcounter += 1
        if self.globalcounter >= 200:
            return
        children = self.states[start_nodeid].children
        for child in children:
            self.state_machine.append(child)
            if child == self.fail_nodeid:
                # this may not be reached
                # so global_timer_nodeid may be None
                self.global_timer_nodeid = start_nodeid
            if child == self.pass_nodeid:
                #print(self.globalcounter)
                self.arrived_pass_node = True
                self.globalcounter = 0
            else:
                self.search_end(child)
            if self.arrived_pass_node == True:
                break
            else:
                self.state_machine.pop()

    def state_machine_obj(self, db_filtered = False):
        # change the state machine to a complex dict, can be changed to JSON obj, for printing
        obj = {}
        if not self.arrived_pass_node:
            print("no state machine can be shown")
            return obj
        
        database = self.database
        if db_filtered:
            database = dict()
        
        states = [] # don't mix up with self.states
        for nodeid in self.state_machine[1 : -1]:
        # using [1 : -1] is to remove start and stop, they are unnecessary
            state = self.states[nodeid]
            nodetype = state.node_type
            if nodetype in ("comment", "decision", "action"):
                continue
            states.append(state.to_json_obj())
            if db_filtered:
                import_list = state.import_list
                for f in import_list:
                    if f["source"] == "database":
                        src_field = f["src_field"]
                        database[src_field] = self.database[src_field]
        obj["sigstd"] = StateMachine.sigstd
        obj["database"] = database
        obj["states"] = states
        return obj
    
    @staticmethod
    def statefile2j(state_file, output_file=None):
        # if we want to specify a output file,
        # directory need to be considered
        out_file = state_file.replace(".states", ".json")

        state_machine = StateMachine()
        state_machine.load(state_file)
        obj = state_machine.state_machine_obj(db_filtered = True)

        fo = open(out_file, "w")
        json.dump(obj, fo, sort_keys=False, indent=4, separators=(',', ': '))
        fo.close()
        print("{} generated".format(out_file))

    @staticmethod
    def state2j(state_name):
        datafiles = StateMachine.datafiles

        state_file = os.path.sep.join([datafiles, state_name + ".states"])
        StateMachine.statefile2j(state_file)

    @staticmethod
    def sequence2j(sequence):
        datafiles = StateMachine.datafiles
        sequence_file = os.path.sep.join([datafiles, sequence + ".sequenceGroup"])
        f = open(sequence_file, "r")
        
        for line in f.readlines():
            line = line.strip()
            if not line.startswith("STATE="):
                continue
            start = 6 # skip "STATE="
            end = line.find(" ", start)
            state_name = line[start : end]
            StateMachine.state2j(state_name)
        f.close()

def usage():
    print('''
    usage: 
        -h, --help      usage info
        -d, --datafiles mgts datafiles dir, like /home/catapult/USERS/hongwehl/datafiles
        -s, --state     state machine name, better use States/<WorkGroup>/<StateName>, like States/CML2/CML2_OG_VFQ
        -g, --sequence  sequence group name, like sequence_itu_vfnl, code will add ".sequenceGroup" when read it
        -f, --file      specify a .states file
        -o, --outfile   specify a outfile name ends with .json
    example: states2j.py -d /home/catapult/USERS/hongweil/datafiles -s States/ITU_Standard/CAP2_IC_WithACR_VFCZ''')
    sys.exit(1)

if __name__ == "__main__":
    # in the future, arguments will be involved, including:
    #   --help -h       usage info
    #   --datafiles     mgts datafiles dir, like /home/catapult/USERS/hongwehl/datafiles
    #   --sigstd        SigStd, default is "CCITT-SS7", this argument is removed because it will got from .states file
    #   --state         state machine name, better use States/<WorkGroup>/<StateName>, like States/CML2/CML2_OG_VFQ
    #   --sequence      sequence group name, like sequence_itu_vfnl, code will add ".sequenceGroup" when read it
    #   --file          specify a .states file
    #   --group         workgroup  no support
    #   --outfile       specify a outfile name ends with .json, no support
    default_datafiles = os.path.sep.join(["/home/catapult/USERS", os.getlogin(), "datafiles"]) # default
    default_sigstd = "CCITT-SS7"

    datafiles = None
    sigstd = default_sigstd
    state_name = None
    sequence = None
    state_file = None
    outfile = None

    try:
        opts, args = getopt.getopt(sys.argv[1 : ], "hd:s:g:f:o:", ["help", "datafiles=", "state=", "sequence=", "file=", "outfile="])
    except getopt.GetoptError as e:
        print(e)
        usage()
    
    for opt, value in opts:
        if opt in ("-h", "--help"):
            usage()
        if opt in ("-d", "--datafiles"):
            datafiles = value
        if opt in ("-s", "--state"):
            state_name = value
        if opt in ("-g", "--sequence"):
            sequence = value
        if opt in ("-f", "--file"):
            state_file = value
        if opt in ("-o", "--outfile"):
            outfile = value

    if state_name == None and sequence == None:
        print("please specify at least --state or --sequence")
        usage()

    if datafiles == None:
        print("using default datafiles dir {}".format(default_datafiles))
        datafiles = default_datafiles

    StateMachine.set_datafiles(datafiles)
    StateMachine.set_sigstd(sigstd)
    
    if sequence != None:
        StateMachine.sequence2j(sequence)

    if state_name != None:
        StateMachine.state2j(state_name)
    
    if state_file != None:
        StateMachine.statefile2j(state_file)
