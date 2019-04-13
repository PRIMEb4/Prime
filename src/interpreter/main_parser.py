import sys

sys.path.insert(0, "../ply-3.11/")

import ply.lex as lex
import ply.yacc as yacc


class p4parser:


	#init structures to help the scanning process
    def __init__(self, src_p4):
        self.it_lines = 0
        self.it_symbols = 0
        self.src_code = src_p4

    #just scan the name (id) of a control flow construct
    #its a naive implementation, since
    def parse_name(self):
        _name = ""
        while self.it_lines < self.code_len:
            it = self.src_code[self.it_lines]
            if(it != '{' and it != '(' and it != ';'):
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
