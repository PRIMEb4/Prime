import sys

from assembler import assemble_P4
from p4module import load_P4module

class commandline:
    def __init__(self):
        self.program = 0
        self.tables_ = []
        self.actions_ = []
        self.parser_ = {}        #dic of states of the parser. Each state maps to a list of attributes
        self.params_ = []
        self.selects_ = {}
        self.extract_ = {}
        self.headers_ = {}
        self.structs_ = {}
        self.emit_ = []
        self.init_catalogue()

    def init_catalogue(self):
        self.applys = """
        apply {
            shadow.apply();
            if(meta.context_control == 1){ \n"""

    #TODO tomorrow    
    #def DFS_(self, v):...

    def verification(self):
        discovered = []
        self.loop_finder('start', discovered)


    def loop_finder(self, vertex, discovered):
        discovered.append(vertex)
        
        #vertex is a state of the packet parser
        if(vertex != 'accept'):
            for transition in self.parser_[vertex]:
                if not self.parser_[vertex][transition] in discovered:
                    self.loop_finder(self.parser_[vertex][transition], discovered)
                else:
                    print('### WARNING-ADM: Loop Found! Uncompatible modules.\n')


    def end_composition(self):
        self.verification()

        catalogue = """{
         meta.context_control = 1;\n"""

        catalogue_params = "("

        for i in range(1, (self.program+1)):
            catalogue = catalogue + "meta.prog" + str(i) + " = prog" + str(i) + ";\n"
            catalogue_params = catalogue_params + "egressSpec_t prog" +str(i)

            self.structs_['metadata'].append({'bit<9>': 'prog'+str(i)})
            #gambia
            if (i != self.program):
                catalogue_params = catalogue_params + ","    

        catalogue_params = catalogue_params + (')')
        catalogue = catalogue + "}\n"

        shadow = """{
           key = {
              hdr.ethernet.dstAddr: exact;
           }
           actions = {
               set_chaining;
               NoAction;
           }
           size = 1024;
           default_action = NoAction();
        }"""

        #more param to the set_chatining
        #i read this comment now and i dont understand it anymore
        #i will keep it here for artistic purposes
        self.actions_.append({'set_chaining': [catalogue_params, catalogue]})
        self.tables_.append({'shadow':shadow})

        self.structs_['metadata'].append({'bit<9>': 'context_control'})

    '''
    carry the operators from the modules already parsed and composed
    it also open a module if it
    '''
    def carry_composition(self, module):
        if not isinstance(module, load_P4module):
            self.program = self.program + 1
            module = load_P4module(module, self.program)
            self.struct_union(module)
            self.parser_union(module)
            self.table_union(module.load)
            self.action_union(module.load)
            self.header_union(module)
            self.deparser_union(module)
        return module

    def build_parser_extension(self):
        #remember that packet extracts are optinal
        #remember also that selects may follow from transitions
        parser_def = """
        parser MyParser(packet_in packet,
                        out headers hdr,
                        inout metadata meta,
                        inout standard_metadata_t standard_metadata) {\n\n"""

        for item in self.parser_:
            parser_def = parser_def + """ state """ + item + """ { \n"""

            if(item in self.extract_):
                parser_def = parser_def + 'packet.extract' + str(self.extract_[item] + ';\n')
            if(item in self.selects_):
                parser_def = parser_def + 'transition select' + str(self.selects_[item] + '{\n')
            for transition in self.parser_[item]:
                if(transition == '*'):
                    parser_def = parser_def + 'transition ' + str(self.parser_[item]['*']) + """;\n"""
                else:
                    parser_def = parser_def + str(transition) + ':' + str(self.parser_[item][transition]) + """; \n"""
            if(item in self.selects_):
                parser_def = parser_def + """}\n"""  #close the state brackets
            parser_def = parser_def + """}\n"""  #close the state brackets
        parser_def = parser_def + "}\n"  #close the parser brackets

        return parser_def

    def calc_sequential_(self, host, extension):
        #print(host.name + extension.name)
        return  """if(meta.prog""" + str(host.module_id) + """==1) { \n
                    """ + ''.join(map(str, host.load.apply_['MyIngress'])) + """
                }if(meta.prog""" + str(extension.module_id) + """==1){
                    """ + ''.join(map(str, extension.load.apply_['MyIngress'])) + """
                }
            """
    def calc_parallel_(self, host, extension):
        return  """if(meta.prog""" + str(host.module_id)  + """==1) { \n
                    """ + ''.join(map(str, host.apply_['MyIngress'])) + """
                }else if(meta.prog""" + str(extension.module_id) + """==1){
                    """ + ''.join(map(str, extension.apply_['MyIngress'])) + """
                }
            """

    def struct_union(self, module):
        for item in module.load.structs_:
            if not item in self.structs_:
                self.structs_[item] = module.load.structs_[item]
            else:
                for transition in module.load.structs_[item]:
                    if not transition in self.structs_[item]:
                        self.structs_[item].append(transition)

    def deparser_union(self, module):
        #TODO reorder transitions
        for item in module.load.emit_:
            if not item in self.emit_:
                self.emit_.append(item)

    #TODO reorder transitions
    def parser_union(self, module):
        for item in module.load.parser_:
            if not item in self.parser_:
                self.parser_[item] = module.load.parser_[item]
            else:
                for transition in module.load.parser_[item]:
                    if not transition in self.parser_[item]:
                        self.parser_[item][transition] = module.load.parser_[item][transition]

        for item in module.load.selects_:
            if not item in self.selects_:
                self.selects_[item] = module.load.selects_[item]

        for item in module.load.extract_:
            if not item in self.extract_:
                self.extract_[item] = module.load.extract_[item]

    #just calculates de union of table definitions
    def table_union(self, module):
        for item in module.tables_:
            if not item in self.tables_:
                self.tables_.append(item)

    def action_union(self, module):
        for item in module.actions_:
            if not item in self.actions_:
                self.actions_.append(item)

    def header_union(self, module):
        for item in module.load.headers_:
            if not item in self.headers_:
                self.headers_[item] = module.load.headers_[item]

    def write_composition_(self, skeleton):
        #if sequential composition the extension id is always 1. Different ids can be used to
        #point to more modules

        self.end_composition()

        self.applys = self.applys + str(skeleton) +"""
            }
        }
        """
        #concatenate applys from the host and the extension
        assembler = assemble_P4()
        assembler.assemble_new_program( self.headers_, self.structs_, self.build_parser_extension(), self.actions_, self.tables_, self.applys, self.emit_)
