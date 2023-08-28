#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import csv
import logging
import requests

from urllib import unquote
from bs4 import BeautifulSoup
from os.path import join, exists

android_api_path = "SourcesAndSinks.txt"
class_cache_path = "class_cache/"
java_api_path = "java_CSVs/"


def get_function_summary(class_name):
    """
    compose the URL for java.*
    https://docs.oracle.com/javase/10/docs/api/java/net/URLConnection.html

    Elements to look at.
    <td class="colFirst"><code><a href="../../java/security/Permission.html" title="class in java.security">Permission</a></code></td>
    <th class="colSecond" scope="row"><code><span class="memberNameLink"><a href="../../java/net/URLConnection.html#getPermission()">getPermission</a></span>()</code></th>


    compose the URL fr android.*
    https://developer.android.com/reference/android/location/Location

    Elements to look at.
    <h3 class="api-name" id="getLatitude()">getLatitude</h3>
    <pre class="api-signature no-pretty-print">
    public double getLatitude ()</pre>
    """
    logging.warning("collecting function signatures for %s", class_name)
    if class_name.startswith(("java.", "javax.")):
        # Get the class API information
        class_name_file = join(class_cache_path, "%s.html" % class_name)
        if not exists(class_name_file):
            class_name_url = "https://docs.oracle.com/javase/10/docs/api/%s.html" % class_name.replace('.', '/')
            content = requests.request('GET', class_name_url)
            open(class_name_file, 'w').write(content.text)

        # Look for Constructor/Method Summary in the doc
        soup = BeautifulSoup(open(class_name_file, "r"), "lxml")
        # class=memberSummary, this yields three sections, fields, constructors, and methods
        sections = filter(lambda s: len(s.findAll("table", {"class", "memberSummary"})) > 0, soup.findAll("section"))
        logging.warning("there are %d sections with memberSummary", len(sections))
        function_signatures = []
        for section in sections:
            if section.find(id="constructor.summary"):
                logging.warning("processing the constructors of %s", class_name)
                constructor_summary = section.find("table", {"class", "memberSummary"})
                for constructor in constructor_summary.findAll("th", {"class": "colConstructorName"}):
                    constructor_url = constructor.find("a").get('href')
                    constructor_signature = unquote(constructor_url).decode('utf8').split('#')[-1]
                    logging.warning("processed constructor %s", constructor_signature)
                    function_signatures.append(constructor_signature)
            elif section.find(id="method.summary"):
                logging.warning("processing the methods of %s", class_name)
                member_summary = section.find("table", {"class", "memberSummary"})
                for member in member_summary.findAll("tr"):
                    if not member.has_attr("id"):
                        logging.debug("skipping %s because no id is available", member)
                        continue
                    member_id = member.get("id")
                    # get modifier and return type
                    method_return = member.find("td", {"class": "colFirst"})
                    # FIXME: deals with no breaking space, x.replace("\xc2\xa0", " ")
                    # https://stackoverflow.com/questions/32419541/python-html-encoding-xc2-xa0
                    if method_return.findChildren("a" , recursive=True):
                        return_info = method_return.find("a")
                        method_return_type = '%s.%s' % (
                            return_info.get('title').replace("\xc2\xa0".decode('utf8'), " ").split(' ')[-1],
                            return_info.text)
                    else:
                        method_return_type = method_return.find("code").text.replace("\xc2\xa0".decode('utf8'), " ").split(" ")[-1]

                    # get method
                    method_url = member.find("th", {"class": "colSecond"}).find("a").get("href")
                    member_name_args = unquote(method_url).decode('utf8').split('#')[-1]
                    member_signature = "%s %s" % (method_return_type, member_name_args)
                    logging.warning("processed method %s id %s", member_signature, member_id)
                    function_signatures.append(member_signature)
            else:
                logging.warning("skipping section of %s", class_name)
        logging.warning("collected %d function signatures", len(function_signatures))
        return function_signatures
    else:
        # class_name.startswith(("android.",))
        # class_name.startswith(("org.apache.",))
        raise Exception("Not handling signature generation for class %s, method %s" % (class_name, method_name))


def get_signatures(class_name, method_name):
    class_functions = get_function_summary(class_name)
    method_signatures = []
    for func in class_functions:
        func_name = func.split('(')[0].strip(' ').split(' ')[-1]
        if func_name == method_name:
            method_signatures.append(func)
    logging.warning("there are %d signatures matching class %s method %s", len(method_signatures), class_name, method_name)
    return method_signatures


with open('../static_java_SourcesAndSinks.txt', 'w') as soot_file:
    all_apis = set()

    # iterate through java apis
    for fname in os.listdir(java_api_path):
        if not fname.endswith('.csv'):
            continue
        reader = csv.DictReader(open(join(java_api_path, fname), 'r'))
        for row in reader:
            if not row['Type']:
                logging.info("ignoring %s %s because it's not assigned a type!", row['Package/Class'], row['Method'])
                continue
            base_type = row['Package/Class']
            # get rid of arguments and return types, if presents
            method_name = row['Method'].split('(')[0].strip(' ').split(' ')[-1]
            method_signatures = get_signatures(base_type, method_name)
            classification = row['Classification']
            if 'Sink' in classification:
                label = "_SINK_"
            elif 'Source' in classification:
                label = "_SOURCE_"
            elif 'Questionable' in classification:
                label = "_SINK_"
            elif 'Both' in classification:
                label = "_BOTH_"
            else:
                raise Exception("Unhandled classification for %s", row)
            for method_signature in method_signatures:
                api_line = '<%s: %s> -> %s\n' % (base_type, method_signature, label)
                if api_line not in all_apis:
                    logging.warning("add method signature %s", method_signature)
                    all_apis.add(api_line)
                    soot_file.write(api_line)

    # iterate through android apis
    with open(android_api_path, 'r') as txt_file:
        for api_line in txt_file:
            if api_line not in all_apis:
                all_apis.add(api_line)
                soot_file.write(api_line)
