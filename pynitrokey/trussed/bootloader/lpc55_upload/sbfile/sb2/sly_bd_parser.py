#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing command (BD) file parser."""

import logging
from numbers import Number
from typing import Any, Dict, List, Optional

from sly import Parser
from sly.lex import Token
from sly.yacc import YaccProduction

from spsdk.exceptions import SPSDKError

from . import sly_bd_lexer as bd_lexer


# pylint: disable=too-many-public-methods,too-many-lines
# too-many-public-methods : every method in the parser represents a syntax rule,
#   this is necessary and thus can't be omitted. From this perspective this check
#   is disabled.
# too-many-lines : the class can't be shortened, as all the methods represent
#   rules.
class BDParser(Parser):
    """Command (BD) file parser.

    The parser is based on SLY framework (python implementation of Lex/YACC)
    and is used to parse the command file, which serves as an input for nxpimage
    utility to create a secure binary in 2.1 format.
    See the documentation for details.
    """

    # Import tokens from lexer. This is required by the parser!
    tokens = bd_lexer.BDLexer.tokens
    # tokens = BDLexer.tokens

    # Uncomment this line to output parser debug file
    # debugfile = "parser.out"

    log = logging.getLogger(__name__)
    log.setLevel(logging.ERROR)

    def __init__(self) -> None:
        """Initialization method."""
        super().__init__()
        self._variables: List[bd_lexer.Variable] = []
        self._sources: List[bd_lexer.Variable] = []
        self._keyblobs: List[Dict] = []
        self._sections: List[bd_lexer.Variable] = []
        self._input: Any = None
        self._bd_file: Dict = {}
        self._parse_error: bool = False
        self._extern: List[str] = []
        self._lexer = bd_lexer.BDLexer()

    def _cleanup(self) -> None:
        """Cleans up allocated resources before next parsing."""
        self._variables = []
        self._keyblobs = []
        self._sections = []
        # for some strange reason, mypy assumes this is a redefinition of _input
        self._input = None
        self._bd_file = {}
        self._parse_error = False
        self._lexer.cleanup()

    def parse(
        self, text: str, extern: Optional[List] = None
    ) -> Optional[Dict]:  # pylint: disable=arguments-differ
        """Parse the `input_text` and returns a dictionary of the file content.

        :param text: command file to be parsed in string format
        :param extern: additional files defined on command line

        :return: dictionary of the command file content or None on Syntax error
        """
        self._cleanup()
        self._extern = extern or []
        # for some strange reason, mypy assumes this is a redefinition of _input
        self._input: Any = text  # type: ignore

        super().parse(self._lexer.tokenize(text))

        if self._parse_error is True:
            print("BD file parsing not successful.")
            return None

        return self._bd_file

    # Operators precedence
    precedence = (
        ("left", "LOR"),
        ("left", "LAND"),
        ("left", "OR"),
        ("left", "XOR"),
        ("left", "AND"),
        ("left", "EQ", "NE"),
        ("left", "GT", "GE", "LT", "LE"),
        ("left", "LSHIFT", "RSHIFT"),
        ("left", "PLUS", "MINUS"),
        ("left", "TIMES", "DIVIDE", "MOD"),
        ("right", "SIZEOF"),
        ("right", "LNOT", "NOT"),
    )

    # pylint: disable=undefined-variable,function-redefined,no-self-use,unused-argument
    # undefined-variable : the module uses underscore decorator to define
    #   each rule, however, this causes issues to mypy and pylint.
    # function-redefined : each rule is identified by a function name and a
    #   decorator. However from code checking tools perspective, this is
    #   function redefinition. Thus we need to disable this rule as well.
    # no-self-use : all 'rules' must be class methods, although they don't use
    #   self. Thus we need to omit this rule.
    # unused-argument : not all token input arguments are always used, especially
    #   in rules which are not supported.
    @_("pre_section_block section_block")  # type: ignore
    def command_file(self, token: YaccProduction) -> None:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        """
        token.pre_section_block.update(token.section_block)
        self._bd_file.update(token.pre_section_block)

    @_("pre_section_block options_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary defining the presection_block.
        """
        options = token.pre_section_block.get("options", {})
        options.update(token.options_block["options"])
        token.pre_section_block["options"] = options
        return token.pre_section_block

    @_("pre_section_block constants_block", "pre_section_block sources_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary defining the presection block.
        """
        token.pre_section_block.update(token[1])
        return token.pre_section_block

    @_("pre_section_block keyblob_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary defining the presection block.
        """
        if token.pre_section_block.get("keyblobs") is None:
            token.pre_section_block["keyblobs"] = []
        token.pre_section_block["keyblobs"].append(token.keyblob_block)
        return token.pre_section_block

    @_("empty")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary defining the presection block.
        """
        return token.empty

    @_("OPTIONS LBRACE option_def RBRACE")  # type: ignore
    def options_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary defining the options block.
        """
        return token.option_def

    @_("option_def IDENT ASSIGN const_expr SEMI")  # type: ignore
    def option_def(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding an option definition.
        """
        # it appears, that in the option block anything can be defined, so
        # we don't check, whether the identifiers defined there are from the
        # allowed options anymore. The code is left just as a reminder.
        # identifier = token.IDENT
        # if identifier in self.allowed_option_identifiers:
        #     self._variables.append(self.Variable(token.IDENT, "option", token.const_expr))
        #     token.option_def["options"].update({token.IDENT : token.const_expr})
        #     return token.option_def
        # else:
        #     column = BDParser._find_column(self._input, token)
        #     print(f"Unknown option in options block at {token.lineno}/{column}: {token.IDENT}")
        #     self.error(token)
        self._variables.append(bd_lexer.Variable(token.IDENT, "option", token.const_expr))
        token.option_def["options"].update({token.IDENT: token.const_expr})
        return token.option_def

    @_("empty")  # type: ignore
    def option_def(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding an empty option definition.
        """
        return {"options": {}}

    @_("CONSTANTS LBRACE constant_def RBRACE")  # type: ignore
    def constants_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        For now, we don't store the constants in the final bd file.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of constants block.
        """
        dictionary: Dict = {}
        return dictionary

    @_("constant_def IDENT ASSIGN bool_expr SEMI")  # type: ignore
    def constant_def(self, token: YaccProduction):
        """Parser rule.

        :param token: object holding the content defined in decorator.
        """
        self._variables.append(bd_lexer.Variable(token.IDENT, "constant", token.bool_expr))

    @_("empty")  # type: ignore
    def constant_def(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding empty constant definition.
        """
        return token.empty

    @_("SOURCES LBRACE source_def RBRACE")  # type: ignore
    def sources_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't store the sources in the final BD file for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the definition of sources
        """
        sources = {}
        for source in self._lexer._sources:
            sources[source.name] = source.value
        return {"sources": sources}

    @_("source_def IDENT ASSIGN source_value SEMI")  # type: ignore
    def source_def(self, token: YaccProduction) -> None:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        """
        new_source = bd_lexer.Variable(token.IDENT, "source", token.source_value)
        self._lexer.add_source(new_source)

    @_("source_def IDENT ASSIGN source_value LPAREN source_attr_list RPAREN SEMI")  # type: ignore
    def source_def(self, token: YaccProduction) -> None:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        """
        # self._sources.append(self.Variable(token.IDENT, "source", token.source_value))
        error_token = Token()
        error_token.lineno = token.lineno
        error_token.index = token._slice[4].index
        self.error(error_token, ": attribute list is not supported")

    @_("empty")  # type: ignore
    def source_def(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding empty content.
        """
        return token.empty

    @_("STRING_LITERAL")  # type: ignore
    def source_value(self, token: YaccProduction) -> str:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: string defining the source value.
        """
        # Everything we read is a string. But strings already contain double quotes,
        # from this perspective we need to remove them, this omit the first and last
        # character.
        return token.STRING_LITERAL[1:-1]

    @_("EXTERN LPAREN int_const_expr RPAREN")  # type: ignore
    def source_value(self, token: YaccProduction) -> str:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: string defining a path defined on command line.
        """
        if token.int_const_expr > len(self._extern) - 1:
            self.error(token, ": extern() out of range")
            return ""
        return self._extern[token.int_const_expr]

    @_("source_attr COMMA source_attr_list")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: empty dictionary as this is not supported right now.
        """
        dictionary = {}
        return dictionary

    @_("source_attr")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: returns dictionary holding content of source attribute.
        """
        return token.source_attr

    @_("empty")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: returns dictionary holding content of empty source attribute list.
        """
        return {}

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def source_attr(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of source file attributes.
        """
        return {token.IDENT: token.const_expr}

    @_("KEYBLOB LPAREN int_const_expr RPAREN LBRACE keyblob_contents RBRACE")  # type: ignore
    def keyblob_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of keyblob block.
        """
        dictionary = {"keyblob_id": token.int_const_expr, "keyblob_content": token.keyblob_contents}
        dictionary["keyblob_id"] = token.int_const_expr
        dictionary["keyblob_content"] = token.keyblob_contents
        self._keyblobs.append(dictionary)
        return dictionary

    # The legacy tool allowed to have multiple definitions inside a keyblob.
    # It has been agreed, that this makes no sense and may be dangerous.
    # However, it may happen, that someone comes with a use cases, where legacy
    # grammar is needed, thus the code has been left untouched just in case.
    # @_("keyblob_contents LPAREN keyblob_options_list RPAREN")
    # def keyblob_contents(self, token):
    #     l = token.keyblob_contents

    #     # Append only non-empty options lists to simplify further processing
    #     if len(token.keyblob_options_list) != 0:
    #         l.append(token.keyblob_options_list)
    #     return l

    # @_("empty")
    # def keyblob_contents(self, token):
    #     return []

    # @_("keyblob_options")
    # def keyblob_options_list(self, token):
    #     return token.keyblob_options

    # @_("empty")
    # def keyblob_options_list(self, token):
    #     # After discussion internal discussion, we will ignore empty definitions in keyblob
    #     # It's not clear, whether this has some effect on the final sb file or not.
    #     # C++ elftosb implementation is able to parse the file even without empty
    #     # parenthesis
    #     return token.empty

    # @_("IDENT ASSIGN const_expr COMMA keyblob_options")
    # def keyblob_options(self, token):
    #     d = {}
    #     d[token.IDENT] = token.const_expr
    #     d.update(token.keyblob_options)
    #     return d

    # @_("IDENT ASSIGN const_expr")
    # def keyblob_options(self, token):
    #     d = {}
    #     d[token.IDENT] = token.const_expr
    #     return d

    # New keyblob grammar!
    @_("LPAREN keyblob_options RPAREN")  # type: ignore
    def keyblob_contents(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list containing options of each keyblob.
        """
        list_ = [token.keyblob_options]

        return list_

    @_("IDENT ASSIGN const_expr COMMA keyblob_options")  # type: ignore
    def keyblob_options(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of keyblob options.
        """
        dictionary = {}
        dictionary[token.IDENT] = token.const_expr
        dictionary.update(token.keyblob_options)
        return dictionary

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def keyblob_options(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the keyblob option.
        """
        dictionary = {}
        dictionary[token.IDENT] = token.const_expr
        return dictionary

    @_("section_block SECTION LPAREN int_const_expr section_options RPAREN section_contents")  # type: ignore
    def section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a section.
        """
        self._sections.append(
            {
                "section_id": token.int_const_expr,
                "options": token.section_options,
                "commands": token.section_contents,
            }
        )
        token.section_block["sections"] += [
            {
                "section_id": token.int_const_expr,
                "options": token.section_options,
                "commands": token.section_contents,
            }
        ]
        return token.section_block

    @_("empty")  # type: ignore
    def section_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding content of empty section.
        """
        token.empty["sections"] = []
        return token.empty

    @_("SEMI section_option_list")  # type: ignore
    def section_options(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of section options.
        """
        return token.section_option_list

    @_("SEMI")  # type: ignore
    def section_options(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of empty section options.
        """
        dictionary = {}
        return dictionary

    @_("empty")  # type: ignore
    def section_options(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of empty section options.
        """
        return token.empty

    @_("section_option_list COMMA section_option")  # type: ignore
    def section_option_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of section options.
        """
        options = {}
        options.update(token.section_option)
        if token.section_option_list:
            token.section_option_list.append(options)
        return token.section_option_list

    @_("section_option")  # type: ignore
    def section_option_list(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding a section option.
        """
        return [token.section_option]

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def section_option(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a section option.
        """
        return {token.IDENT: token.const_expr}

    @_("LBRACE statement RBRACE")  # type: ignore
    def section_contents(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the section statements.
        """
        return token.statement

    @_("LE SOURCE_NAME SEMI")  # type: ignore
    def section_contents(self, token: YaccProduction) -> None:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": <= <source_name> syntax is not supported right now.")

    @_("statement basic_stmt SEMI")  # type: ignore
    def statement(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list holding section statements.
        """
        list_ = [] + token.statement
        list_.append(token.basic_stmt)
        return list_

    @_("statement from_stmt")  # type: ignore
    def statement(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support from_stmt for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of from_stmt.
        """
        dictionary = {}
        return dictionary

    @_("statement if_stmt")  # type: ignore
    def statement(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support if statements for now.

        :param token: object holding the content defined in decorator.
        """
        # return token.statement + token.if_stmt

    @_("statement encrypt_block")  # type: ignore
    def statement(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list containing the encrypt statement.
        """
        list_ = [] + token.statement
        list_.append(token.encrypt_block)
        return list_

    @_("statement keywrap_block")  # type: ignore
    def statement(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list containing the keywrap statement.
        """
        list_ = [] + token.statement
        list_.append(token.keywrap_block)
        return list_

    @_("empty")  # type: ignore
    def statement(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: empty list.
        """
        # return empty statement list
        return []

    @_("KEYWRAP LPAREN int_const_expr RPAREN LBRACE LOAD BINARY_BLOB GT int_const_expr SEMI RBRACE")  # type: ignore
    def keywrap_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the keywrap block content.
        """
        dictionary = {"keywrap": {"keyblob_id": token.int_const_expr0}}
        load_cmd = {"address": token.int_const_expr1, "values": token.BINARY_BLOB}
        dictionary["keywrap"].update(load_cmd)
        return dictionary

    @_("ENCRYPT LPAREN int_const_expr RPAREN LBRACE load_stmt SEMI RBRACE")  # type: ignore
    def encrypt_block(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the encrypt block content.
        """
        dictionary = {"encrypt": {"keyblob_id": token.int_const_expr}}
        dictionary["encrypt"].update(token.load_stmt.get("load"))
        return dictionary

    @_(  # type: ignore
        "load_stmt",
        "call_stmt",
        "jump_sp_stmt",
        "mode_stmt",
        "message_stmt",
        "erase_stmt",
        "enable_stmt",
        "reset_stmt",
        "keystore_stmt",
        "version_stmt",
    )
    def basic_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of defined statements.
        """
        return token[0]

    @_("LOAD load_opt load_data load_target")  # type: ignore
    def load_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a load statement.
        """
        # pattern with load options means load -> program command
        if token.load_data.get("pattern") is not None and token.load_opt.get("load_opt") is None:
            cmd = "fill"
        else:
            cmd = "load"
        dictionary: Dict = {cmd: {}}
        dictionary[cmd].update(token.load_opt)
        dictionary[cmd].update(token.load_data)
        dictionary[cmd].update(token.load_target)
        return dictionary

    @_("empty")  # type: ignore
    def load_opt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load options.
        """
        return token.empty

    @_("'@' int_const_expr")  # type: ignore
    def load_opt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load options.
        """
        return {"load_opt": token.int_const_expr}

    @_("IDENT")  # type: ignore
    def load_opt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load options.
        """
        return {"load_opt": token.IDENT}

    @_("int_const_expr")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        if isinstance(token.int_const_expr, str):
            self.error(token, f": identifier '{token.int_const_expr}' is not a source identifier.")
            retval = {"N/A": "N/A"}
        else:
            retval = {"pattern": token.int_const_expr}

        return retval

    @_("STRING_LITERAL")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        return {"file": token.STRING_LITERAL[1:-1]}

    @_("SOURCE_NAME")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        for source in self._lexer._sources:
            if token.SOURCE_NAME == source.name:
                return {"file": source.value}

        # with current implementation, this code won't be ever reached. In case
        # a not defined source file is used as `load_data`, the parser detects
        # it as a different rule:
        #
        # load_data ::= int_const_expr
        #
        # which evaluates as false... however, this fragment is left just in
        # in case something changes.
        self.error(token, ": source file not defined")
        return {"file": "N/A"}

    @_("section_list")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        self.error(token, ": section list is not supported")
        dictionary = {}
        return dictionary

    @_("section_list FROM SOURCE_NAME")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        self.error(token, "section list using from is not supported")
        dictionary = {}
        return dictionary

    @_("BINARY_BLOB")  # type: ignore
    def load_data(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load data.
        """
        # no_spaces = "".join(token.BINARY_BLOB.split())

        return {"values": token.BINARY_BLOB}

    @_("GT PERIOD")  # type: ignore
    def load_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the load target.
        """
        self.error(token, ": '.' as load destination is not supported right now")
        dictionary = {}
        return dictionary

    @_("GT address_or_range")  # type: ignore
    def load_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of load target.
        """
        return token.address_or_range

    @_("empty")  # type: ignore
    def load_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: empty dictionary.
        """
        self.error(token, ": empty load target is not supported right now.")
        return token.empty

    @_("ERASE mem_opt address_or_range")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of erase statement.
        """
        dictionary: Dict = {token.ERASE: {}}
        dictionary[token.ERASE].update(token.address_or_range)
        dictionary[token.ERASE].update(token.mem_opt)
        return dictionary

    @_("ERASE mem_opt ALL")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of erase statement.
        """
        dictionary: Dict = {token.ERASE: {"address": 0x00, "flags": 0x01}}
        dictionary[token.ERASE].update(token.mem_opt)
        return dictionary

    @_("ERASE UNSECURE ALL")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of erase statement.
        """
        return {"erase": {"address": 0x00, "flags": 0x02}}

    @_("ENABLE mem_opt int_const_expr")  # type: ignore
    def enable_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of enable statement.
        """
        dictionary: Dict = {token.ENABLE: {}}
        dictionary[token.ENABLE].update(token.mem_opt)
        dictionary[token.ENABLE]["address"] = token.int_const_expr
        return dictionary

    @_("section_list COMMA section_ref")  # type: ignore
    def section_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the section list content.
        """
        dictionary = {}
        return dictionary

    @_("section_ref")  # type: ignore
    def section_list(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a section reference.
        """
        return token.section_ref

    @_("NOT SECTION_NAME")  # type: ignore
    def section_ref(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a section reference.
        """
        self.error(token, ": section reference is not supported.")
        dictionary = {}
        return dictionary

    @_("SECTION_NAME")  # type: ignore
    def section_ref(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a section reference.
        """
        self.error(token, ": section reference is not supported.")
        return {token.SECTION_NAME}

    @_("int_const_expr")  # type: ignore
    def address_or_range(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of an address.
        """
        address_start = token.int_const_expr
        return {"address": address_start}

    @_("int_const_expr RANGE int_const_expr")  # type: ignore
    def address_or_range(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of an address range.
        """
        address_start = token.int_const_expr0
        length = token.int_const_expr1 - address_start
        return {"address": address_start, "length": length}

    @_("SOURCE_NAME QUESTIONMARK COLON IDENT")  # type: ignore
    def symbol_ref(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": symbol reference is not supported.")

    @_("call_type call_target call_arg")  # type: ignore
    def call_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a call statement.
        """
        dictionary: Dict = {token.call_type: {}}
        dictionary[token.call_type].update(token.call_target)
        dictionary[token.call_type].update(token.call_arg)
        return dictionary

    @_("CALL", "JUMP")  # type: ignore
    def call_type(self, token: YaccProduction) -> str:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: string representing 'call' or 'jump'
        """
        return token[0]

    @_("int_const_expr")  # type: ignore
    def call_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a call_target.
        """
        return {"address": token.int_const_expr}

    @_("SOURCE_NAME")  # type: ignore
    def call_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a call target.
        """
        self.error(token, ": source name as call target is not supported.")
        dictionary = {}
        return dictionary

    @_("symbol_ref")  # type: ignore
    def call_target(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a call target.
        """
        self.error(token, ": symbol reference as call target is not supported.")
        dictionary = {}
        return dictionary

    @_("LPAREN RPAREN")  # type: ignore
    def call_arg(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding an empty call argument.
        """
        dictionary = {}
        return dictionary

    @_("LPAREN int_const_expr RPAREN")  # type: ignore
    def call_arg(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding a call argument.
        """
        return {"argument": token.int_const_expr}

    @_("empty")  # type: ignore
    def call_arg(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding an empty call argument.
        """
        return token.empty

    @_("JUMP_SP int_const_expr call_target call_arg")  # type: ignore
    def jump_sp_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content jump statement.
        """
        dictionary: Dict = {"jump": {}}
        dictionary["jump"]["spreg"] = token.int_const_expr
        dictionary["jump"].update(token.call_target)
        dictionary["jump"].update(token.call_arg)
        return dictionary

    @_("RESET")  # type: ignore
    def reset_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of a reset statement.
        """
        return {"reset": {}}

    @_("FROM SOURCE_NAME LBRACE in_from_stmt RBRACE")  # type: ignore
    def from_stmt(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": from statement not supported.")

    @_("basic_stmt SEMI")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list of statements.
        """
        return token.basic_stmt

    @_("if_stmt")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list of statements.
        """
        return token.if_stmt

    @_("empty")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: empty list.
        """
        return []

    @_("MODE int_const_expr")  # type: ignore
    def mode_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return:
        """
        self.error(token, ": mode statement is not supported")
        dictionary: Dict = {}
        return dictionary

    @_("message_type STRING_LITERAL")  # type: ignore
    def message_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the message statement.
        """
        dictionary: Dict = {}
        return dictionary

    @_("INFO", "WARNING", "ERROR")  # type: ignore
    def message_type(self, token: YaccProduction) -> Dict:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: empty dictionary.
        """
        self.error(token, ": info/warning/error messages are not supported.")
        dictionary: Dict = {}
        return dictionary

    @_("KEYSTORE_TO_NV mem_opt address_or_range")  # type: ignore
    def keystore_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content keystore statement.
        """
        dictionary = {token.KEYSTORE_TO_NV: {}}
        dictionary[token.KEYSTORE_TO_NV].update(token.mem_opt)
        dictionary[token.KEYSTORE_TO_NV].update(token.address_or_range)
        return dictionary

    @_("KEYSTORE_FROM_NV mem_opt address_or_range")  # type: ignore
    def keystore_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content keystore statement.
        """
        dictionary = {token.KEYSTORE_FROM_NV: {}}
        dictionary[token.KEYSTORE_FROM_NV].update(token.mem_opt)
        dictionary[token.KEYSTORE_FROM_NV].update(token.address_or_range)
        return dictionary

    @_("IDENT")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> None:
        """Parser rule.

        Unsupported syntax right now.

        :param token: object holding the content defined in decorator.
        """
        # search in variables for token.IDENT variable and get it's value
        return {"mem_opt": token.IDENT}

    @_("'@' int_const_expr")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of memory type.
        """
        dictionary = {"mem_opt": token.int_const_expr}
        return dictionary

    @_("empty")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> None:
        """Parser rule.

        Unsupported syntax right now.

        :param token: object holding the content defined in decorator.
        """
        return token.empty

    @_("VERSION_CHECK sec_or_nsec fw_version")  # type: ignore
    def version_stmt(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of version check statement.
        """
        dictionary: Dict = {token.VERSION_CHECK: {}}
        dictionary[token.VERSION_CHECK].update(token.sec_or_nsec)
        dictionary[token.VERSION_CHECK].update(token.fw_version)
        return dictionary

    @_("SEC")  # type: ignore
    def sec_or_nsec(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of version check type.
        """
        dictionary = {"ver_type": 0}
        return dictionary

    @_("NSEC")  # type: ignore
    def sec_or_nsec(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of version check type.
        """
        dictionary = {"ver_type": 1}
        return dictionary

    @_("int_const_expr")  # type: ignore
    def fw_version(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: dictionary holding the content of fw version.
        """
        dictionary = {"fw_version": token.int_const_expr}
        return dictionary

    @_("IF bool_expr LBRACE statement RBRACE else_stmt")  # type: ignore
    def if_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: list of if statements.
        """
        self.error(token, ": if & if-else statement is not supported.")
        if token.bool_expr:
            return token.statement

        return token.else_stmt

    @_("ELSE LBRACE statement RBRACE")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list of else statements.
        """
        return token.statement

    @_("ELSE if_stmt")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: list of else if statements.
        """
        return token.if_stmt

    @_("empty")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> List:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: empty list.
        """
        list_ = []
        return list_

    @_("STRING_LITERAL")  # type: ignore
    def const_expr(self, token: YaccProduction) -> str:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: string.
        """
        return token.STRING_LITERAL[1:-1]

    @_("bool_expr")  # type: ignore
    def const_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: boolean value as a result of constant expression.
        """
        return token.bool_expr

    @_("expr")  # type: ignore
    def int_const_expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: Number as a result of an expression.
        """
        return token.expr

    @_("DEFINED LPAREN IDENT RPAREN")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: boolean value as a result if some identifier is defined.
        """
        return token.IDENT in self._variables

    @_(  # type: ignore
        "bool_expr LT bool_expr",
        "bool_expr LE bool_expr",
        "bool_expr GT bool_expr",
        "bool_expr GE bool_expr",
        "bool_expr EQ bool_expr",
        "bool_expr NE bool_expr",
        "bool_expr LAND bool_expr",
        "bool_expr LOR bool_expr",
        "LPAREN bool_expr RPAREN",
    )
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: boolean value as a result of boolean expression.
        """
        operator = token[1]
        if operator == "<":
            return token.bool_expr0 < token.bool_expr1
        if operator == "<=":
            return token.bool_expr0 <= token.bool_expr1
        if operator == ">":
            return token.bool_expr0 > token.bool_expr1
        if operator == ">=":
            return token.bool_expr0 >= token.bool_expr1
        if operator == "==":
            return token.bool_expr0 == token.bool_expr1
        if operator == "!=":
            return token.bool_expr0 != token.bool_expr1
        if operator == "&&":
            return token.bool_expr0 and token.bool_expr1
        if operator == "||":
            return token.bool_expr0 or token.bool_expr1

        return token[1]

    @_("int_const_expr")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: boolean value as a result of a boolean expression.
        """
        return token.int_const_expr

    @_("LNOT bool_expr")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: boolean value as a result of logical not expression.
        """
        return not token.bool_expr

    @_("IDENT LPAREN SOURCE_NAME RPAREN")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        :return: boolean value (at the moment always False, as not supported).
        """
        # I've absolutely no clue, what this rule can mean or be for???
        self.error(token, ": IDENT ( SOURCE_NAME ) is not supported.")
        return False

    @_(  # type: ignore
        "expr PLUS expr",
        "expr MINUS expr",
        "expr TIMES expr",
        "expr DIVIDE expr",
        "expr MOD expr",
        "expr LSHIFT expr",
        "expr RSHIFT expr",
        "expr AND expr",
        "expr OR expr",
        "expr XOR expr",
        "expr PERIOD INT_SIZE",
        "LPAREN expr RPAREN",
    )
    def expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: number as a result of an expression.
        """
        operator = token[1]
        if operator == "+":
            return token.expr0 + token.expr1
        if operator == "-":
            return token.expr0 - token.expr1
        if operator == "*":
            return token.expr0 - token.expr1
        if operator == "/":
            return token.expr0 // token.expr1
        if operator == "%":
            return token.expr0 % token.expr1
        if operator == "<<":
            return token.expr0 << token.expr1
        if operator == ">>":
            return token.expr0 >> token.expr1
        if operator == "&":
            return token.expr0 & token.expr1
        if operator == "|":
            return token.expr0 | token.expr1
        if operator == "^":
            return token.expr0 ^ token.expr1
        if operator == ".":
            char = token.INT_SIZE
            if char == "w":
                return token[0] & 0xFFFF
            if char == "h":
                return token[0] & 0xFF
            if char == "b":
                return token[0] & 0xF
        # LPAREN expr RPAREN
        return token[1]

    @_("INT_LITERAL")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: integer number as a terminal.
        """
        return token.INT_LITERAL

    @_("IDENT")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: number stored under identifier.
        """
        # we need to convert the IDENT into a value stored under that identifier
        # search the variables and check, whether there is a name of IDENT
        for var in self._variables:
            if var.name == token.IDENT:
                return var.value

        return token.IDENT

    @_("symbol_ref")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": symbol reference is not supported.")

    @_("unary_expr")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: number as a result of unary expression.
        """
        return token.unary_expr

    @_("SIZEOF LPAREN symbol_ref RPAREN")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": sizeof operator is not supported")

    @_("SIZEOF LPAREN IDENT RPAREN")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Parser rule.

        We don't support this rule for now.

        :param token: object holding the content defined in decorator.
        """
        self.error(token, ": sizeof operator is not supported")

    @_("PLUS expr", "MINUS expr")  # type: ignore
    def unary_expr(self, token: YaccProduction) -> Number:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: number as a result of unary expression.
        """
        sign = token[0]
        number = token.expr
        if sign == "-":
            number = -number

        return number

    @_("")  # type: ignore
    def empty(self, token: YaccProduction) -> Dict:
        """Parser rule.

        :param token: object holding the content defined in decorator.
        :return: empty dictionary.
        """
        dictionary: Dict = {}
        return dictionary

    @staticmethod
    def _find_column(text: str, token: YaccProduction) -> int:
        """Finds the column of token in input.

        :param text: input file being parsed
        :param token: object holding the content defined in decorator.
        :return: column based on token index.
        """
        last_cr = text.rfind("\n", 0, token.index)
        if last_cr < 0:
            last_cr = 0
        else:
            last_cr += 1
        column = (token.index - last_cr) + 1
        return column

    @staticmethod
    def _find_line(text: str, line_num: int) -> str:
        """Finds the line in text based on line number.

        :param text: text to return required line.
        :param line_num: line number to return.
        :return: line 'line_num" in 'text'.
        """
        lines = text.split("\n")

        return lines[line_num]

    def error(
        self, token: YaccProduction, msg: str = ""
    ) -> YaccProduction:  # pylint: disable=arguments-differ
        """Syntax error handler.

        On syntax error, we set an error flag and read the rest of input file
        until end to terminate the process of parsing.

        :param token: object holding the content defined in decorator.
        :param msg: error message to use.

        :raises SPSDKError: Raises error with 'msg' message.
        """
        self._parse_error = True

        if token:
            lineno = getattr(token, "lineno", -1)
            if lineno != -1:
                column = BDParser._find_column(self._input, token)
                error_line = BDParser._find_line(self._input, lineno - 1)
                raise SPSDKError(
                    f"bdcompiler:{lineno}:{column}: error{msg}\n\n{error_line}\n"
                    + (column - 1) * " "
                    + "^\n"
                )

            raise SPSDKError(f"bdcompiler: error{msg}\n")

        raise SPSDKError("bdcompiler: unspecified error.")
