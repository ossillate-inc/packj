package osssanitizer.astgen_java;

import java.io.File;
import java.io.IOException;
import java.util.Locale;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;

import proto.Ast.AstLookupConfig;
import osssanitizer.astgen_java.util.ProtoBufferUtil;
import osssanitizer.astgen_java.util.SootConfigUtil;


public class Main 
{
    private org.apache.commons.cli.Options options = null;
    private Map<String, String> optionToValue = null;
    private Map<String, Boolean> optionToBooleanValue = null;
    
    public String getOption(String option) {
    	return optionToValue.getOrDefault(option, "");
    }
    
    public String getOptionOrDefault(String option, String defau) {
    	return optionToValue.getOrDefault(option, defau);
    }
    
    public Boolean getBooleanOption(String option) {
    	return optionToBooleanValue.getOrDefault(option, false);
    }

    private void buildOptions() {
        options = new Options();
        options.addOption("help", false, "Print the help message.");
        options.addOption("inpath", true, "Path to the input directory or file.");
        options.addOption("config", true, "Optional path to the filter of nodes, stored in proto buffer format (AstLookupConfig in ast.proto).");
        options.addOption("outfile", true, "Path to the output file.");
        options.addOption("sig_outfile", true, "Optional path to the class signature output file.");
        options.addOption("package_name", true, "Package name of the specified input.");
        options.addOption("package_version", true, "Package version of the specified input.");
        
        // Soot specific options
        options.addOption("intype", true, "Type of input file, default to JAR. Can be APK|DEX|JAR|CLASS|SOURCE.");
        options.addOption("process_dir", true, "The process directory of the input file. For CLASS input, it should consider package folders.");
        options.addOption("android_jar_dir", true, "android jars directory. Required for APK and DEX.");
        options.addOption("thread_count", true, "The number of threads to use, default to #Cores.");
        options.addOption("show_stats", false, "Show the stats of different analysis steps. Optional, for debugging.");
        options.addOption("soot_out_dir", true, "soot out dir, needed in soot to produce intermediate results. Optional, for debugging.");
        options.addOption("keep_soot_output", false, "Keep the soot intermediate output files. Optional, for debugging.");
        options.addOption("keep_bb_info", false, "Keep the basic block level information, needed for Centroid computation.");
    }

	private void parseOptions(String[] args) {
		Locale locale = new Locale("en", "US");
		Locale.setDefault(locale);

		CommandLineParser parser = new DefaultParser();
		CommandLine commandLine;

		try {
			commandLine = parser.parse(options, args);

			commandLine.getArgs();
			org.apache.commons.cli.Option[] clOptions = commandLine.getOptions();

			optionToValue = new HashMap<String, String>();
			optionToBooleanValue = new HashMap<String, Boolean>();
			for (int i = 0; i < clOptions.length; i++) {
				org.apache.commons.cli.Option option = clOptions[i];
				if (option.hasArg()) {
					String opt = option.getOpt();
					optionToValue.put(opt, commandLine.getOptionValue(opt));
				} else {
					String opt = option.getOpt();
					optionToBooleanValue.put(opt, commandLine.hasOption(opt));
				}
			}
		} catch (ParseException ex) {
			ex.printStackTrace();
			return;
		}
	}
	
	private void analyze(String inpath, String outfile, String sigOutfile, String config, String pkgName, String pkgVersion, SootConfigUtil sootConfig) {
		AstLookupConfig configpb = null;
		try {
			configpb = (AstLookupConfig) ProtoBufferUtil.loadFromFile(AstLookupConfig.getDefaultInstance(), new File(config), false);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		ClassSignatures cs = new ClassSignatures(configpb, sootConfig);
		cs.analyze(inpath, outfile, sigOutfile, pkgName, pkgVersion);
	}
	
    /**
	 * Parse arguments and call analyze().
	 * 
	 * @param args
	 * @throws Exception
	 */
    public static void main( String[] args )throws Exception {
		// 1. enable assertion and build options
		ClassLoader.getSystemClassLoader().setDefaultAssertionStatus(true);
		Main analyzer = new Main();
		analyzer.buildOptions();
		analyzer.parseOptions(args);
		if (analyzer.getBooleanOption("help")) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp("java -jar target/astgen-java-*.jar", analyzer.options);
			return;
		}
		
		// 2. set soot config
		SootConfigUtil sootConfig = new SootConfigUtil();
		sootConfig.setIntype(analyzer.getOptionOrDefault("intype", "JAR"));
		sootConfig.setSootOutDir(analyzer.getOptionOrDefault("soot_out_dir", null));
		sootConfig.setProcessDir(analyzer.getOptionOrDefault("process_dir", null));
		sootConfig.setAndroidJarDir(analyzer.getOptionOrDefault("android_jar_dir", null));
		sootConfig.setThreadCount(Integer.parseInt(analyzer.getOptionOrDefault("thread_count", "-1")));
		sootConfig.setShowStats(analyzer.getBooleanOption("show_stats"));
		sootConfig.setKeepSootOutput(analyzer.getBooleanOption("keep_soot_output"));
		sootConfig.setKeepBBInfo(analyzer.getBooleanOption("keep_bb_info"));
		
		// 3. call analyze
		analyzer.analyze(analyzer.getOption("inpath"), analyzer.getOption("outfile"), analyzer.getOption("sig_outfile"), 
				analyzer.getOption("config"), analyzer.getOption("package_name"), analyzer.getOption("package_version"), sootConfig);
	}
}
