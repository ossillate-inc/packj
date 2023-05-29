#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re

# Replace the nth occurrence of a string
# Inspired from https://stackoverflow.com/questions/35091557/replace-nth-occurrence-of-substring-in-string
def nth_replace(string, old, new, n):
    if string.count(old) >= n:
        left_join = old
        right_join = old
        groups = string.split(old)
        nth_split = [left_join.join(groups[:n]), right_join.join(groups[n:])]
        return new.join(nth_split)
    return string.replace(old, new)


# Display the found vulnerability with basic information like the line
def display(path, payload, vulnerability, line, declaration_text, declaration_line, colored, occurrence):
    # # Potential vulnerability found :  SQL Injection
    # header = "Potential vulnerability found : {}".format(payload[1])

    # # Line  25  in test/sqli.php
    # line = "n°{} in {}".format(line, path)

    # # Code : include($_GET['patisserie'])
    # vuln = nth_replace("".join(vulnerability), colored, colored, occurrence)
    # vuln = "{}({})".format(payload[0], vuln)

    # # Final Display
    # rows, columns = os.popen('stty size', 'r').read().split()
    # print("-" * (int(columns) - 1))
    # print("Name        \t{}".format(header))
    # print("-" * (int(columns) - 1))
    # print("Line              {}".format(line))
    # print("Code              {}".format(vuln))

    # # Declared at line 1 : $dest = $_GET['who'];
    # if "$_" not in colored:
    #     declared = "Undeclared in the file"
    #     if declaration_text != "":
    #         declared = "Line n°{} : {}".format(declaration_line, declaration_text)

    #     print("Declaration       {}".format(declared))

    # # Small delimiter
    # print("")
   # "{}:[{'file_path':{},'api_name':Not Decleared!, 'lineno':{}}]".format(payload[1],path,line)
    return {payload[1]:[{'filepath':path,'lineno':line}]}


# Find the line where the vulnerability is located
def find_line_vuln(payload, vulnerability, content):
    content = content.split('\n')
    for i in range(len(content)):
        if payload[0] + '(' + vulnerability[0] + vulnerability[1] + vulnerability[2] + ')' in content[i]:
            return str(i - 1)
    return "-1"


# Find the line where the entry point is declared
# TODO: should be an array of the declaration and modifications
def find_line_declaration(declaration, content):
    content = content.split('\n')
    for i in range(len(content)):
        if declaration in content[i]:
            return str(i)
    return "-1"


# Format the source code in order to improve the detection
def clean_source_and_format(content):
    # Clean up - replace tab by space
    content = content.replace("    ", " ")

    # Quickfix to detect both echo("something") and echo "something"
    content = content.replace("echo ", "echo(")
    content = content.replace(";", ");")
    return content


# Check the line to detect an eventual protection
def check_protection(payload, match):
    for protection in payload:
        if protection in "".join(match):
            return True
    return False


# Check exception - When it's a function($SOMETHING) Match declaration $SOMETHING = ...
def check_exception(match):
    exceptions = ["_GET", "_REQUEST", "_POST", "_COOKIES", "_FILES"]
    for exception in exceptions:
        if exception in match:
            return True
    return False


# Check declaration
def check_declaration(content, vuln, path):
    # Follow and parse include, then add it's content
    regex_declaration = re.compile("(include.*?|require.*?)\\([\"\'](.*?)[\"\']\\)")
    includes = regex_declaration.findall(content)

    # Path is the path of the current scanned file, we can use it to compute the relative include
    for include in includes:
        relative_include = os.path.dirname(path) + "/"
        try:
            path_include = relative_include + include[1]
            with open(path_include, 'r') as f:
                content = f.read() + content
        except Exception as e:
            return False, "", ""

    # Extract declaration - for ($something as $somethingelse)
    vulnerability = vuln[1:].replace(')', '\\)').replace('(', '\\(')
    regex_declaration2 = re.compile("\\$(.*?)([\t ]*)as(?!=)([\t ]*)\\$" + vulnerability)
    declaration2 = regex_declaration2.findall(content)
    if len(declaration2) > 0:
        return check_declaration(content, "$" + declaration2[0][0], path)

    # Extract declaration - $something = $_GET['something']
    regex_declaration = re.compile("\\$" + vulnerability + "([\t ]*)=(?!=)(.*)")
    declaration = regex_declaration.findall(content)
    if len(declaration) > 0:

        # Check constant then return True if constant because it's false positive
        declaration_text = "$" + vulnerability + declaration[0][0] + "=" + declaration[0][1]
        line_declaration = find_line_declaration(declaration_text, content)
        regex_constant = re.compile("\\$" + vuln[1:] + "([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{}_\\(\\)@\\.,!: ]*?[\"\')]*?);")
        false_positive = regex_constant.match(declaration_text)

        if false_positive:
            return True, "", ""
        return False, declaration_text, line_declaration

    return False, "", ""
