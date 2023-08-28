import csv
import json
import logging
import os

from os.path import join


# Android specific sources and sinks
# https://raw.githubusercontent.com/secure-software-engineering/FlowDroid/master/soot-infoflow-android/SourcesAndSinks.txt
android_api_path = "SourcesAndSinks.txt"
# Java specific sources and sinks
java_api_path = "java_CSVs/"
count = 1

#data = {}
#data['type'] = 'FUNCTION_DECL_REF_EXPR'
source_ids = []
sink_ids = []
danger_ids = []

with open('../astgen_java_smt.config', 'w') as astgen_file:
    # iterate through java apis
    all_apis = set()
    for fname in os.listdir(java_api_path):
        if not fname.endswith('.csv'):
            continue

        reader = csv.DictReader(open(join(java_api_path, fname)))
        for row in reader:
            if not row['Type']:
                logging.info("ignoring %s %s because it's not assigned a type!", row['Package/Class'], row['Method'])
                continue
            base_type = row['Package/Class']
            # get rid of arguments and return types, if presents
            method_name = row['Method'].split('(')[0].strip(' ').split(' ')[-1]
            qualified_api = '%s.%s' % (base_type, method_name)
            # skip duplicated function entries
            if qualified_api in all_apis:
                logging.warning("ignoring duplicated function entry %s", qualified_api)
                continue
            # generate the file content
            all_apis.add(qualified_api)
            astgen_file.write('apis {\n')
            astgen_file.write('\ttype: FUNCTION_DECL_REF_EXPR\n')
            astgen_file.write('\tname: "' + method_name + '"\n')
            astgen_file.write('\tfull_name: "' + qualified_api + '"\n')
            astgen_file.write('\tbase_type: "' + base_type + '"\n')
            if row['Type'].startswith('SOURCE_'):
                astgen_file.write('\tfunctionality: SOURCE\n')
                astgen_file.write('\tsource_type: ' + row['Type'] + '\n')
            elif row['Type'].startswith('SINK_'):
                astgen_file.write('\tfunctionality: SINK\n')
                astgen_file.write('\tsink_type: ' + row['Type'] + '\n')
            else:
                raise Exception("Unexpected type %s for %s", row['Type'], qualified_api)
            astgen_file.write('\tid: ' + str(count) + '\n')
            astgen_file.write('}\n')
            if any(s in row['Classification'] for s in ('Source', 'Both')):
                source_ids.append(count)
            if any(s in row['Classification'] for s in ('Sink', 'Both')):
                sink_ids.append(count)
            if 'Questionable' in row['Classification']:
                danger_ids.append(count)
            count += 1

    # iterate through android apis
    package_to_type = {
        "org.apache.http": ["SOURCE_NETWORK", "SINK_NETWORK"],
        "android.net": ["SOURCE_NETWORK", "SINK_NETWORK"],
        "java.net": ["SOURCE_NETWORK", "SINK_NETWORK"],
        "java.io": ["SOURCE_FILE", "SINK_FILE"],
        "java.util.Calendar": ["SOURCE_CALENDAR", "SINK_CALENDAR"],
        "android.database": ["SOURCE_DATABASE", "SINK_DATABASE"],
        "android.content": ["SOURCE_DATABASE", "SINK_DATABASE"],
        "android.location": ["SOURCE_DATABASE", "SINK_DATABASE"],
        "android.telephony": ["SOURCE_UNIQUE_IDENTIFIER", "SINK_SMS_MMS"],
        "android.os": ["SINK_SYSTEM"],
        "android.media": ["SOURCE_FILE", "SINK_FILE"],
        "android.util": ["SINK_LOG"],
        "android.accounts": ["SOURCE_ACCOUNT"],
        "android.bluetooth": ["SOURCE_BLUETOOTH"],
        "android.app": ["SINK_SYSTEM"],
        "android.provider.Browser": ["SOURCE_BROWSER", "SINK_BROWSER"]
        # TODO: dynamically update the permissions here!
    }

    def get_type(pkg_base, prefix):
        packages = [pkg for pkg in package_to_type.keys() if pkg_base.startswith(pkg)]
        if not packages:
            return []
        if len(packages) > 1:
            raise Exception("Found more than one matching packages %s for %s" % (packages, pkg_base))
        package = packages[0]
        return [pkg_type for pkg_type in package_to_type[package] if pkg_type.startswith(prefix)]

    with open(android_api_path, 'r') as android_reader:
        for line in android_reader:
            line = line.strip()
            if not (line and not line.startswith('%') and '->' in line):
                continue
            generic_api, classification = line.split('->')
            generic_api = generic_api.split('> ')[0].strip('<')
            base_type, method_signature = generic_api.split(':')
            method_name = method_signature.split('(')[0].strip(' ').split(' ')[-1]
            qualified_api = '%s.%s' % (base_type, method_name)
            if qualified_api in all_apis:
                logging.warning("ignoring duplicated function entry %s", qualified_api)
                continue
            # generate the file content
            all_apis.add(qualified_api)
            astgen_file.write('apis {\n')
            astgen_file.write('\ttype: FUNCTION_DECL_REF_EXPR\n')
            astgen_file.write('\tname: "' + method_name + '"\n')
            astgen_file.write('\tfull_name: "' + qualified_api + '"\n')
            astgen_file.write('\tbase_type: "' + base_type + '"\n')
            logging.warning("analyzing %s", qualified_api)
            if 'BOTH' in classification:
                danger_ids.append(count)
                astgen_file.write('\tfunctionality: SINK\n')
                astgen_file.write('\tsink_type: ' + get_type(base_type, "SINK")[0] + '\n')
            elif 'SOURCE' in classification:
                source_ids.append(count)
                astgen_file.write('\tfunctionality: SOURCE\n')
                astgen_file.write('\tsource_type: ' + get_type(base_type, "SOURCE")[0] + '\n')
            elif 'SINK' in classification:
                sink_ids.append(count)
                astgen_file.write('\tfunctionality: SINK\n')
                astgen_file.write('\tsink_type: ' + get_type(base_type, "SINK")[0] + '\n')
            else:
                raise Exception("Unexpected classification %s for %s", classification, qualified_api)
            astgen_file.write('\tid: ' + str(count) + '\n')
            astgen_file.write('}\n')
            count += 1

    # write sources to smt
    astgen_file.write('smt_formula: "((' + ' | '.join([str(sid) for sid in source_ids]) + ') & (')

    # write sinks to smt
    astgen_file.write(' | '.join([str(sid) for sid in sink_ids]) + ')) | (')

    # write "dangers" to smt
    astgen_file.write(' | '.join([str(did) for did in danger_ids]) + ')"')
