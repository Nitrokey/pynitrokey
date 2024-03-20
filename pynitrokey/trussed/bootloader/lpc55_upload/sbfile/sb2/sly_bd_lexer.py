#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Lexer for command (BD) files used by parser."""

from typing import List, Union

from sly import Lexer
from sly.lex import Token


# pylint: disable=undefined-variable,invalid-name,no-self-use
# undefined-variable : the lexer uses '_' as a decorator, which throws undefined
#   variable error. We can't do much with it.
# invalid-name : tokens are defined as upper case. However this violates the
#   snake cae naming style. We can't do much, as this is required by the lexer.
# no-self-use : the public methods must be defined as class methods although
#   the self is not used at all.
class Variable:
    """Class representing a variable in command file."""

    def __init__(self, name: str, token: str, value: Union[str, int, float]) -> None:
        """Initializer.

        :param name: name of identifier (variable)
        :param token: type of variable (option, constant etc.)
        :param value: the content of the variable
        """
        self.name = name
        self.t = token
        self.value = value

    def __str__(self) -> str:
        """Returns a string with variable info.

        i.e.
        "<var_name>, <var_type>, <var_value>"

        :return: string
        """
        return f"{self.name}, {self.t}, {self.value}"


class BDLexer(Lexer):
    """Lexer for bd files."""

    def __init__(self) -> None:
        """Initializer."""
        self._sources: List[Variable] = []

    def cleanup(self) -> None:
        """Resets the lexers internals into initial state."""
        self._sources.clear()

    def add_source(self, source: Variable) -> None:
        """Append an identifier of source type into list.

        :param source: identifier defined under sources block in BD file
        """
        self._sources.append(source)

    # List of reserved keywords
    reserved = {
        "call": "CALL",
        "constants": "CONSTANTS",
        "extern": "EXTERN",
        "erase": "ERASE",
        "false": "FALSE",
        "filters": "FILTERS",
        "from": "FROM",
        "jump": "JUMP",
        "load": "LOAD",
        "mode": "MODE",
        "else": "ELSE",
        "info": "INFO",
        "error": "ERROR",
        "enable": "ENABLE",
        "keywrap": "KEYWRAP",
        "keystore_to_nv": "KEYSTORE_TO_NV",
        "keystore_from_nv": "KEYSTORE_FROM_NV",
        "all": "ALL",
        "no": "NO",
        "options": "OPTIONS",
        "raw": "RAW",
        "section": "SECTION",
        "sources": "SOURCES",
        "switch": "SWITCH",
        "true": "TRUE",
        "yes": "YES",
        "if": "IF",
        "defined": "DEFINED",
        "warning": "WARNING",
        "sizeof": "SIZEOF",
        "unsecure": "UNSECURE",
        "jump_sp": "JUMP_SP",
        "keyblob": "KEYBLOB",
        "reset": "RESET",
        "encrypt": "ENCRYPT",
        "version_check": "VERSION_CHECK",
        "sec": "SEC",
        "nsec": "NSEC",
    }

    # List of token names. This is always required
    tokens = [
        "COMMENT",
        "IDENT",
        "SOURCE_NAME",
        "BINARY_BLOB",
        "INT_LITERAL",
        "STRING_LITERAL",
        "RANGE",
        "ASSIGN",
        "INT_SIZE",
        "SECTION_NAME",
        #'SYMBOL_REF', replaced with a non-terminal symbol_ref
        # Operators (+,-,*,/,%,|,&,~,^,<<,>>, ||, &&, !, <, <=, >, >=, ==, !=)
        "PLUS",
        "MINUS",
        "TIMES",
        "DIVIDE",
        "MOD",
        "OR",
        "AND",
        "NOT",
        "XOR",
        "LSHIFT",
        "RSHIFT",
        "LOR",
        "LAND",
        "LNOT",
        "LT",
        "LE",
        "GT",
        "GE",
        "EQ",
        "NE",
        # Delimiters ( ) { } , . ; :
        "LPAREN",
        "RPAREN",
        "LBRACE",
        "RBRACE",
        "COMMA",
        "PERIOD",
        "SEMI",
        "COLON",
        # Special characters
        "QUESTIONMARK",
        "DOLLAR",
    ] + list(reserved.values())

    literals = {"@"}

    # A regular expression rules with some action code
    # The order of these functions MATTER!!! Make sure you know what you are
    # doing, when changing the order of function declarations!!!
    @_(r"(//.*)|(/\*(.|\s)*?\*/)|(\#.*)")  # type: ignore
    def COMMENT(self, token: Token) -> None:
        """Token rule to detect comments (including multiline).

        Allowed comments are C/C++ like comments '/* */', '//' and bash-like
        comments starting with '#'.

        :param token: token matching a comment
        """
        # Multiline comments are counted as a single line. This causes us troubles
        # in t_newline(), which treats the multiline comment as a single line causing
        # a mismatch in the final line position.
        # From this perspective we increment the linenumber here by the total
        # number of lines - 1 (the subtracted 1 gets counted byt t_newline)
        self.lineno += len(token.value.split("\n")) - 1

    # It's not possible to detect INT_SIZE token while whitespaces are present between period and
    # letter in real use case, because of regex engine limitation in positive lookbehind.
    @_(r"(?<=(\d|[0-9a-fA-F])\.)[ \t]*[whb]")  # type: ignore
    def INT_SIZE(self, token: Token) -> Token:
        """Token rule to detect numbers appended with w/h/b.

        Example:
        my_number = 4.b
        my_number = 1.h
        my_number = 3.w

        The w/h/b defines size (Byte, Halfword, Word). This should be taken into
        account during number computation.

        :param token: token matching int size

        :return: Token representing the size of int literal
        """
        return token

    @_(r"[_a-zA-Z][_a-zA-Z0-9]*")  # type: ignore
    def IDENT(self, token: Token) -> Token:
        """Token rule to detect identifiers.

        A valid identifier can start either with underscore or a letter followed
        by any numbers of underscores, letters and numbers.

        If the name of an identifier is from the set of reserved keywords, the
        token type is replaced with the keyword name, otherwise the token is
        of type 'IDENT'.
        Values of type TRUE/YES, FALSE/NO are replaces by 1 or 0 respectively.

        :param token: token matching an identifier pattern
        :return: Token representing identifier
        """
        # it may happen that we find an identifier, which is a keyword, in such
        # a case remap the type from IDENT to reserved word (i.e. keyword)
        token_type = self.reserved.get(token.value, "IDENT")
        if token_type in ["TRUE", "YES"]:
            token.type = "INT_LITERAL"
            token.value = 1
        elif token_type in ["FALSE", "NO"]:
            token.type = "INT_LITERAL"
            token.value = 0
        else:
            token.type = token_type
            # check, whether the identifier is under sources, in such case
            # change the type to SOURCE_NAME
            for source in self._sources:
                if source.name == token.value:
                    token.type = "SOURCE_NAME"
                    break
        return token

    @_(r"\b([0-9]+[K]?|0[xX][0-9a-fA-F]+)\b|'.*'")  # type: ignore
    def INT_LITERAL(self, token: Token) -> Token:
        """Token rule to detect integer literals.

        An int literal may be represented as a number in decimal form appended
        with a 'K' or number in hexadecimal form.

        Example:
        1024
        1K # same as above
        -256
        0x25

        Lexer converts the detected string into a number. String literals
        appended with 'K' are multiplied by 1024.

        :param token: token matching integer literal pattern
        :return: Token representing integer literal
        """
        number = token.value
        if number[0] == "'" and number[-1] == "'":
            # transform 'dude' into '0x64756465'
            number = "0x" + bytearray(number[1:-1], "utf-8").hex()
            number = int(number, 0)
        elif number[-1] == "K":
            number = int(number[:-1], 0) * 1024
        else:
            number = int(number, 0)

        token.value = number
        return token

    @_(r"\$[\w\.\*\?\-\^\[\]]+")  # type: ignore
    def SECTION_NAME(self, token: Token) -> Token:
        """Token rule to detect section names.

        Section names start with a dollar sign ($) glob-type expression that
        can match any number of ELF sections.

        Example:
        $section_[ab]
        $math*

        :param token: token matching section name pattern
        :return: Token representing section name
        """
        return token

    @_(r"\{\{([0-9a-fA-F]{2}| )+\}\}")  # type: ignore
    def BINARY_BLOB(self, token: Token) -> Token:
        """Token rule to detect binary blob.

        A binary blob is a sequence of hexadecimal bytes in double curly braces.

        Example:
        {{aa bb cc 1F 3C}}

        :param token: token matching binary blob pattern
        :return: Token representing binary blob
        """
        # return just the content between braces
        value = token.value[2:-2]

        token.value = "".join(value.split())
        return token

    # A string containing ignored characters (spaces and tabs)
    ignore = " \t"

    @_(r"\n")  # type: ignore
    def newline(self, token: Token) -> None:
        """Token rule to detect new lines.

        On new line character the line number count is incremented.

        :param token: token matching new line character
        """
        self.lineno += len(token.value)

    # Operators regular expressions
    PLUS = r"\+"
    MINUS = r"-"
    TIMES = r"\*"
    DIVIDE = r"/"
    MOD = r"%"
    NOT = r"~"
    XOR = r"\^"
    LSHIFT = r"<<"
    RSHIFT = r">>"
    LOR = r"\|\|"
    OR = r"\|"
    LAND = r"&&"
    AND = r"&"
    LE = r"<="
    LT = r"<"
    GE = r">="
    GT = r">"
    EQ = r"=="
    NE = r"!="
    LNOT = r"!"

    # Tokens regular expressions
    STRING_LITERAL = r"\".*\""
    RANGE = r"\.\."

    # Assignment operator regular expressions
    ASSIGN = r"="

    # Delimiters regular expressions
    LPAREN = r"\("
    RPAREN = r"\)"
    LBRACE = r"\{"
    RBRACE = r"\}"
    COMMA = r","
    PERIOD = r"\."
    SEMI = r";"
    COLON = r":"

    # Special characters
    QUESTIONMARK = r"\?"
    DOLLAR = r"\$"

    # Error handling rule
    def error(self, t: Token) -> Token:
        """Token error handler.

        The lexing index is incremented so lexing can continue, however, an
        error token is returned. The token contains the whole text starting
        with the detected error.

        :param t: invalid token.
        :return: the invalid token.
        """
        self.index += 1
        t.value = t.value[0]
        return t
