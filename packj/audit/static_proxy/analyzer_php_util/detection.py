#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import math
from packj.audit.static_proxy.analyzer_php_util.indicators import *
from packj.audit.static_proxy.analyzer_php_util.function import *

result_count = 0
result_files = 0
final_dict ={}

# Analyse the source code of a single page
def analysis(path):
    global result_count
    global result_files
    result_files += 1
    with open(path, 'r', encoding='utf-8', errors='replace') as content_file:

        # Clean source for a better detection
        content = content_file.read()
        content = clean_source_and_format(content)

        # Hardcoded credentials (work as an exception, it's not function based)
        credz = ['pass', 'secret', 'token', 'pwd']
        for credential in credz:
            content_pure = content.replace(' ', '')

            # detect all variables
            regex_var_detect = "\$[\w\s]+\s?=\s?[\"|'].*[\"|']|define\([\"|'].*[\"|']\)"
            regex = re.compile(regex_var_detect , re.I)
            matches = regex.findall(content_pure)
            
            # If we find a variable with a constant for a given indicator
            for vuln_content in matches:
                if credential in vuln_content.lower():
                    payload = ["", "SINK_UNCLASSIFIED", []]
                    final_dict.update(add_vuln_var(payload, path, vuln_content, content, regex_var_detect))
                
        
        # Detection of RCE/SQLI/LFI/RFI/RFU/XSS/...
        for payload in payloads:
            regex = re.compile(payload[0] + regex_indicators)
            matches = regex.findall(content.replace(" ", "(PLACEHOLDER"))

            for vuln_content in matches:

                # Handle "require something" vs "require(something)"
                # Dirty trick to force a parenthesis before the function's argument
                vuln_content = list(vuln_content)
                for i in range(len(vuln_content)):
                    vuln_content[i] = vuln_content[i].replace("(PLACEHOLDER", " ")
                    vuln_content[i] = vuln_content[i].replace("PLACEHOLDER", "")
                occurence = 0

                # Security hole detected, is it protected ?
                if not check_protection(payload[2], vuln_content):
                    declaration_text, line = "", ""

                    # Managing multiple variable in a single line/function
                    sentence = "".join(vuln_content)
                    regex = re.compile(regex_indicators[2:-2])
                    for vulnerable_var in regex.findall(sentence):
                        false_positive = False
                        occurence += 1

                        # No declaration for $_GET, $_POST ...
                        if not check_exception(vulnerable_var[1]):
                            # Look for the declaration of $something = xxxxx
                            false_positive, declaration_text, line = check_declaration(
                                content,
                                vulnerable_var[1],
                                path)
                            # Set false positive if protection is in the variable's declaration
                            is_protected = check_protection(payload[2], declaration_text)
                            false_positive = is_protected if is_protected else false_positive
                        # Display all the vuln
                        line_vuln = find_line_vuln(payload, vuln_content, content)

                        # Check for not $dest="constant"; $dest='cste'; $dest=XX;
                        if "$_" not in vulnerable_var[1]:
                            if "$" not in declaration_text.replace(vulnerable_var[1], ''):
                                false_positive = True

                        if not false_positive:
                            result_count = result_count + 1
                            final_dict.update(display(path, payload, vuln_content, line_vuln, declaration_text, line, vulnerable_var[1], occurence))


# Run thru every files and subdirectories
def recursive(dir, progress):
    try:
        for name in os.listdir(dir):
            # Targetting only PHP Files
            if os.path.isfile(os.path.join(dir, name)):
                if ".php" in os.path.join(dir, name):
                    analysis(dir + "/" + name)
            else:
                recursive(dir + "/" + name, progress)

    except OSError as e:
        print("Error 404 - Not Found, maybe you need more right ?" + " " * 30)
        exit(-1)


# Display basic informations about the scan
def finalresult():
    return final_dict



def add_vuln_var(payload, path, vuln_content, page_content, regex_var_detect, occurence=1):
    # Get the line of the vulnerability
    line_vuln = -1
    splitted_content = page_content.split('\n')
    for i in range(len(splitted_content)):
        regex = re.compile(regex_var_detect, re.I)
        matches = regex.findall(splitted_content[i])
        if len(matches) > 0:
            line_vuln = i

    # display the result
    

    # increment the global vulnerability count
    global result_count
    result_count = result_count + 1
    
    return display(
        path,           # path
        payload,        # payload
        vuln_content,   # vulnerability
        line_vuln,      # line
        vuln_content,   # declaration_text
        str(line_vuln), # declaration_line
        vuln_content,   # colored
        occurence,      # occurence
    )