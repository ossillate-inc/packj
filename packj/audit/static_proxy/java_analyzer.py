import logging
from os.path import isdir, dirname, join, basename, splitext
from packj.util.enum_util import LanguageEnum
from packj.util.job_util import exec_command, read_proto_from_file, write_proto_to_file
from packj.util.compress_files import get_file_with_meta
from packj.audit.static_proxy.static_base import StaticAnalyzer
from packj.audit.proto.python.ast_pb2 import PkgAstResults
from packj.util.job_util import write_dict_to_file


class JavaAnalyzer(StaticAnalyzer):
    def __init__(self):
        super(JavaAnalyzer, self).__init__()
        self.language = LanguageEnum.java

    def astgen(self, inpath, outfile, root=None, configpath=None, pkg_name=None, pkg_version=None, evaluate_smt=False):
        analyze_path, is_decompress_path, outfile, root, configpath = self._sanitize_astgen_args(
            inpath=inpath, outfile=outfile, root=root, configpath=configpath, language=self.language)
        
        composition = {
			"Files" : [],
			"Functions" : [],
			"Calls" : [],
		}
        
        allfiles, infiles, bins, root = self._get_infiles(inpath=analyze_path, root=root, language=self.language)
        
        for infile in allfiles:
            try:
                all_source = open(infile, 'r').read()
            except Exception as e:
                logging.warning("Failed to read file %s: %s" % (infile, str(e)))
                continue
            
            try:
                file_details = {
					"Name"	: infile,
					"LoC"	: len(all_source.split('\n')),
					"Native" : infile in infiles,
					"Binary" : infile in bins,
				}
                composition["Files"].append(file_details)
            except Exception as e:
                logging.debug("Failed to parse FILE %s ast details: %s!" % (infile, str(e)))
                
            if infile not in infiles:
                continue
            
        astgen_cmd = ['java', '-jar', 'target/astgen-java-1.0.0-jar-with-dependencies.jar', '-inpath', analyze_path, '-outfile', outfile, '-config', configpath]
                
        if analyze_path.endswith((".apk", ".dex")):
            # processing android apps requires android.jar
            astgen_cmd.extend(['-android_jar_dir', 'platforms/'])
            if analyze_path.endswith(".apk"):
                astgen_cmd.extend(['-intype', 'APK' '-process_dir', analyze_path])
            elif analyze_path.endswith(".dex"):
                astgen_cmd.extend(['-intype', 'DEX', '-process_dir', analyze_path])
        elif analyze_path.endswith((".java",)):
            astgen_cmd.extend(['-intype', 'SOURCE', '-process_dir', dirname(analyze_path)])
        elif analyze_path.endswith((".class",)):
            astgen_cmd.extend(['-intype', 'CLASS', '-process_dir', dirname(analyze_path)])
        elif analyze_path.endswith((".jar",)):
            # this is the default input type
            astgen_cmd.extend(['-intype', 'JAR', '-process_dir', analyze_path])
        elif analyze_path.endswith((".aar",)):
            # aar contains /classes.jar
            # https://developer.android.com/studio/projects/android-library
            astgen_cmd.extend(['-android_jar_dir', 'platforms/'])
            aar_file = get_file_with_meta(analyze_path)
            class_jar_content = aar_file.accessor.read('classes.jar')
            analyze_path_jar = join(dirname(analyze_path), splitext(basename(analyze_path))[0] + '.jar')
            open(analyze_path_jar, 'wb').write(class_jar_content)
            astgen_cmd.extend(['-intype', 'JAR', '-process_dir', analyze_path_jar])
        elif analyze_path.endswith((".war",)):
            # war contains lots of jar files in /WEB-INF/lib/
            # http://one-jar.sourceforge.net/
            logging.error("Not handling .war file yet: %s", analyze_path)
        else:
            logging.error("Input path has unexpected suffix: %s", analyze_path)
        # root is not used here
        if pkg_name is not None:
            astgen_cmd.extend(['-package_name', pkg_name])
        if pkg_version is not None:
            astgen_cmd.extend(['-package_version', pkg_version])
        try:
            stdout, stderr, error = exec_command("java astgen", astgen_cmd, cwd="packj/audit/static_proxy/astgen-java")
            assert not error, "could not generate AST"
        except Exception as e:
            logging.debug("Failed to exec %s: %s!" % (astgen_cmd, str(e)))
            return None
        resultpb = PkgAstResults()
        read_proto_from_file(resultpb, filename=outfile, binary=False)
        
        try:
            logging.warning('writing to %s' % (outfile+'.json'))
            write_dict_to_file(composition, outfile + '.json')
        except Exception as e:
            logging.debug("failed to write ast_details: %s" % (str(e)))

        write_proto_to_file(resultpb, filename=outfile, binary=False)

        # clean up residues
        self._cleanup_astgen(analyze_path=analyze_path, is_decompress_path=is_decompress_path)