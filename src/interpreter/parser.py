class parser_control_flow():

    tables_= []        #list of tables. I think that a dict would be efficiently
    actions_ = []      #list of actions. Same for dict...    
    parser_ = {}        #dic of states of the parser. Each state maps to a list of attributes
    params_ = []
    selects_ = {}
    extract_ = {}
    headers_ = {}
    structs_ = {}
    emit_ = []

    #init structures to help the scanning process
    def __init__(self, src_p4):
        self.buffer_ = []
        self.tables = []
        self.parser_name = ''
        self.parser_param = ''
        self.it_lines = 0
        self.it_symbols = 0
        self.src_code = src_p4
        self.code_len = len(src_p4)
        self.apply_ = {}         #a dic of every apply found on each control. The control id is the dic index
        self.scan_control()


    def parse_name(self):
        """
        name
        : nonTypeName
        | TYPE
        | ERROR
        ;"""

        _name = ""
        while self.it_lines < self.code_len:
            it = self.src_code[self.it_lines]
            if(it != '{' and it != '(' and it != ';'):
                _name = _name + it
            else:
                break
            self.it_lines = self.it_lines + 1
        return _name.strip()

    def scan_type(self):
        _type = ""
        while self.it_lines < self.code_len:
            it = self.src_code[self.it_lines]
            if(it != '{' and it != '(' and it != ';' and it != ' '):
                _type = _type + it
            else:
                break
            self.it_lines = self.it_lines + 1
        return _type.strip()


    def parse_till_symbol(self, symbol):
        _name = ""
        while self.it_lines < self.code_len:
            it = self.src_code[self.it_lines]
            if(it != symbol):
                _name = _name + it
            else:
                break
            self.it_lines = self.it_lines + 1
        return _name.strip()

    #scan constructs that have identificator such as
    #controls, actions and tables definitions
    def scan_def(self, dic_):
        it_symbols = 0
        #ignore whitespaces --
        while self.it_lines < self.code_len and (self.src_code[self.it_lines] == ' ' or self.src_code[self.it_lines] == '\n'):
            self.it_lines = self.it_lines + 1

        while self.it_lines < self.code_len:
            if dic_[it_symbols] == '*':
                return True
            else:
                if(dic_[it_symbols] == self.src_code[self.it_lines]):
                    it_symbols = it_symbols + 1
                else:
                    return False
            self.it_lines = self.it_lines + 1

    #load param definitions to a different structure
    #this is necessary just for parsing and rewriting
    def parse_params(self):
        params_ = ""

        while True:
            params_ = params_ + self.src_code[self.it_lines]
            if self.src_code[self.it_lines] == ')':
                break
            self.it_lines = self.it_lines + 1
        self.it_lines = self.it_lines + 1
        return params_

    #just load a block between '{' and '}'
    #all recursive calls inside the block are loaded with
    def parse_codeBlock(self):
        colchetes = 0
        local_buffer = []

        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == '{'):
                colchetes = colchetes + 1
            elif(self.src_code[self.it_lines] == '}'):
               local_buffer.append(self.src_code[self.it_lines])
               self.it_lines = self.it_lines + 1
               if(colchetes == 1):
                   return local_buffer
               else:
                   colchetes = colchetes - 1

            local_buffer.append(self.src_code[self.it_lines])
            self.it_lines = self.it_lines + 1
        return -1

    def scan_control_block(self, block_name):
        """transition = '{' table | action | apply '}' """
        """
        controlDeclaration
                : controlTypeDeclaration optConstructorParameters
                /*no type parameters allowed in controlTypeDeclaration*/
                '{' controlLocalDeclarations APPLY controlBody '}'
                ;"""


        colchetes = 0

        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == '{'):
                colchetes = colchetes + 1
            elif(self.src_code[self.it_lines] == '}'):
               self.it_lines = self.it_lines + 1
               if(colchetes == 1):
                   return #magic
               else:
                   colchetes = colchetes - 1
            elif(self.src_code[self.it_lines] == 't'):
                    #try to read table
                    if(self.scan_def("table*")):
                        name = self.parse_name()
                        block = self.parse_codeBlock()
                        self.tables_.append({name : block})
            elif(self.src_code[self.it_lines] == 'a'):
                if(self.src_code[self.it_lines+1] == 'c'):
                    if(self.scan_def("action*")):
                            name = self.parse_name()
                            params = self.parse_params()
                            block = self.parse_codeBlock()
                            self.actions_.append({name : [params,block]})
                elif(self.scan_def("apply*")):
                    if(block_name == 'MyDeparser'):
                        self.scan_deparser()
                    else:
                        print('scan maluco' + block_name)
                        self.apply_[block_name] = self.parse_codeBlock()
                        print('scan maluco fudeu' + block_name)
                        print (self.apply_[block_name])
            self.it_lines = self.it_lines + 1

    def scan_struct(self, name):
        """struct := '{' vars '}'"""
        """vars := var_type var_name ';' | vars | e"""

        self.parse_till_symbol('{')
        self.it_lines = self.it_lines + 1

        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == '}'):
                self.it_lines = self.it_lines + 1
                return
            if(self.src_code[self.it_lines] == ' ' or self.src_code[self.it_lines] == '\n'):
                self.it_lines = self.it_lines + 1
                continue
            var_type = self.scan_type()
            var_name = self.parse_name()
            self.parse_till_symbol(';')
            self.structs_[name].append( { var_type : var_name } )
            self.it_lines = self.it_lines + 1

    def scan_deparser(self):
        'packet.extract ( header name )'

        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == '}'):
                return
            if(self.scan_def('packet.emit*')):
                self.emit_.append(self.parse_params())
                self.parse_till_symbol(';')
            self.it_lines = self.it_lines + 1

    #scan the construct inside a control or parsers
    def scan_control(self):
        """declaration
                        : constantDeclaration
                        | externDeclaration
                        | actionDeclaration
                        | parserDeclaration
                        | typeDeclaration
                        | controlDeclaration
                        | instantiation
                        | errorDeclaration
                        | matchKindDeclaration
                        ;"""

        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == 'c'):
                if(self.scan_def("control*")):
                    name = self.parse_name()
                    params = self.parse_params()
                    block = self.scan_control_block(name)
            elif(self.src_code[self.it_lines] == 'p'):
                if(self.scan_def("parser*")):
                    self.parser_name = self.parse_name()
                    self.parser_param = self.parse_params()
                    self.scan_parse_control()
            elif(self.src_code[self.it_lines] == 'h'):
                if(self.scan_def("header*")):
                    name = self.parse_name()
                    header = self.parse_codeBlock()
                    self.headers_[name] = header
            elif(self.src_code[self.it_lines] == 's'):
                if(self.scan_def("struct*")):
                    name = self.parse_name()
                    #self.structs_[name] = self.parse_codeBlock()
                    self.structs_[name] = []
                    self.scan_struct(name)

            self.it_lines = self.it_lines + 1

    def scan_parse_control(self):
        colchetes = 0
        while self.it_lines < self.code_len:
            if(self.src_code[self.it_lines] == '}'):
                self.it_lines = self.it_lines + 1
                return #magic
            elif(self.scan_def("state*")):
                name = self.parse_name()
                self.parser_[name] = {}
                self.parse_stateBlock(name)
            self.it_lines = self.it_lines + 1
    '''
    this method scan the transtions inside a select
    it ignores whitespaces and newlines marks
    '''
    def parse_select(self, state):
        '''
        {param : state}
        add transition param -> state
        '''
        colchetes = 1
        while self.it_lines < self.code_len:
            car = self.src_code[self.it_lines]
            if(car == '\n' or car == ' '):
                self.it_lines = self.it_lines + 1
                continue
            if(car == '{'):
                colchetes = colchetes + 1
            elif(car == '}'):
               self.it_lines = self.it_lines + 1
               if(colchetes == 1):
                   return #magic
               else:
                   colchetes = colchetes - 1
            else:
                param = self.parse_till_symbol(':')
                self.it_lines = self.it_lines + 1
                next_state = self.parse_till_symbol(';')
                self.it_lines = self.it_lines + 1
                self.parser_[state][param] = next_state
            self.it_lines = self.it_lines + 1

    #parse transitions of states
    def read_transition(self, state):
        '''
        #transition := select(atribute) | accept | reject
        #select attribute from the select
        #the selection works as a simple switch case for transitions
        '''
        name = self.parse_name()

        if(name == 'select'):
            self.selects_[state] = self.parse_params()
            self.parse_select(state)
        else: #no selects implicates one single transition
            self.parser_[state]['*'] = name


    def parse_stateBlock(self, state_id):
        '''
        #stateBlock := packet_extract | transition
        #in case there is a packet extraction we need to save it
        #the need to save it is to rewrite the code
        #and also to search for non-determinism
        #there is a need to read lookahead too
        '''
        car = self.src_code[self.it_lines]

        while car == ' ' or car == '\n' or car == '{':
            self.it_lines = self.it_lines+1
            car = self.src_code[self.it_lines]

        if(self.src_code[self.it_lines] == 'p'):
            if(self.scan_def('packet.extract*')):
                #need to save packet extract params to rewrite the code
                params = self.parse_params()
                self.extract_[state_id] = params  
                self.parse_till_symbol(';')
                self.it_lines = self.it_lines + 1
        if(self.scan_def('transition*')):
            self.read_transition(state_id)
        self.parse_till_symbol('}')

        self.it_lines = self.it_lines + 1
