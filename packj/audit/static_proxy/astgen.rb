require 'parser/current'
require 'optparse'
require 'pathname'

# require_relative vs. require in google protobuf generated code. google is unresponsive.
# https://github.com/protocolbuffers/protobuf/pull/1138
# https://github.com/protocolbuffers/protobuf/pull/2478
# https://stackoverflow.com/questions/6671318/understanding-rubys-load-paths
$LOAD_PATH.unshift(File.expand_path('../proto/ruby/', File.dirname(__FILE__)))
require "ast_pb"


class RubyDeclRefVisitor <  Parser::AST::Processor
    # Reference:
    # parser/lib/parser/ast/processor.rb
    attr_accessor   :decl_refs

    def initialize(buffer, configpb, debug=false)
        @buffer = buffer
        @debug = debug
        @save_feature = false
        @func_only = false
        if !configpb.nil?
            @save_feature = configpb.save_feature
            @func_only = configpb.func_only
        end

        # initialize the declaration filters
        @decl_refs_filter_set = nil
        if !configpb.nil?
            @decl_refs_filter_set = {}
            configpb.apis.each do |api|
                if api.type == :FUNCTION_DECL_REF_EXPR
                    if @func_only
                        if !api.base_type.nil? && !api.base_type.empty?
                            name_to_check = ".#{api.name}"
                        else
                            name_to_check = api.name
                        end
                        @decl_refs_filter_set[name_to_check] = 1
                    else
                        @decl_refs_filter_set[api.full_name] = 1
                    end
                end
            end
        end
        # the collected declaration references
        @decl_refs = []
    end

    def on_def(node)
        name, args_node, body_node = *node
        super
        if @debug
            puts "Found a method body for #{name} (#{args_node})"
        end
    end

    def on_defs(node)
        definee_node, name, args_node, body_node = *node
        super
        if @debug
            puts "Found a singleton method body for #{definee_node} #{name} (#{args_node})"
        end
    end

    def get_node_text(node)
        # parser/lib/parser/source/buffer.rb
        # parser/lib/parser/source/range.rb
        return @buffer.slice(node.loc.expression.begin_pos...node.loc.expression.end_pos)
    end

    def on_xstr(node)
        decl_ref = {}
        decl_ref['name'] = 'builtin_xstring'
        decl_ref['base'] = nil
        decl_ref['source_range'] = node.loc
        decl_ref['source_text'] = get_node_text(node)
        # arguments
        if node.children.nil?
            decl_ref['args'] = nil
        else
            args = []
            node.children.each do |arg_node|
                args << get_node_text(arg_node)
            end
            decl_ref['args'] = args
        end
        # base is nil, so directly use name
        name_to_check = decl_ref['name']
        if @decl_refs_filter_set.nil? || @decl_refs_filter_set.has_key?(name_to_check)
            @decl_refs << decl_ref
        end
        super
        if @debug
            puts "Found an execute-string for #{node}"
        end
    end

    def on_send(node)
        receiver_node, method_name, *arg_nodes = *node
        decl_ref = {}
        decl_ref['name'] = method_name.to_s
        if receiver_node.nil?
            decl_ref['base'] = nil
        else
            decl_ref['base'] = get_node_text(receiver_node)
        end
        # node.loc.line/column/last_line/last_column
        decl_ref['source_range'] = node.loc
        decl_ref['source_text'] = get_node_text(node)
        if arg_nodes.nil?
            decl_ref['args'] = nil
        else
            args = []
            arg_nodes.each do |arg_node|
                args << get_node_text(arg_node)
            end
            decl_ref['args'] = args
        end
        if decl_ref['base'].nil?
            full_name = decl_ref['name']
        else
            full_name = "#{decl_ref['base']}.#{decl_ref['name']}"
        end
        if @func_only
            if !decl_ref['base'].nil? && !decl_ref['base'].empty?
                name_to_check = ".#{decl_ref['name']}"
            else
                name_to_check = decl_ref['name']
            end
        else
            name_to_check = full_name
        end
        if @decl_refs_filter_set.nil? || @decl_refs_filter_set.has_key?(name_to_check)
            @decl_refs << decl_ref
        end
        super
        if @debug
            puts "Found a method call to receiver: #{receiver_node}, name: #{method_name}, args: #{arg_nodes}"
        end
    end
end


def getInfiles(inpath, root)
    infiles = []
    if File.exist?(inpath)
        if File.directory?(inpath)
            # add *.rb files
            # https://ruby-doc.org/core-2.2.1/Dir.html#method-i-each
            rbfiles = File.join(inpath, "**", "*.rb")
            Dir.glob(rbfiles) do |rbfile|
                infiles << File.absolute_path(rbfile)
            end
            # Rakefile files
            rakefiles = File.join(inpath, "**", "Rakefile")
            Dir.glob(rakefiles) do |rakefile|
                infiles << File.absolute_path(rakefile)
            end
            if root.nil?
                root = inpath
            end
            root = File.absolute_path(root)
        else
            infiles << File.absolute_path(inpath)
            if root.nil?
                root = File.dirname(inpath)
            end
            root = File.absolute_path(root)
        end
    else
        raise "inpath #{inpath} doesn't exist!"
    end
    return infiles, root
end


def getFilepb(infile, root)
    filepb = Proto::FileInfo.new
    filepb.filename = File.basename(infile)
    filepb.relpath = Pathname.new(File.dirname(infile)).relative_path_from(Pathname.new(root)).to_s
    filepb.file = Pathname.new(infile).relative_path_from(Pathname.new(root)).to_s
    filepb.directory = root
    return filepb
end


def getApiResult(base, name, args, source_text, source_range, filepb)
    api_resultpb = Proto::AstNode.new
    api_resultpb.type = :FUNCTION_DECL_REF_EXPR
    api_resultpb.name = name
    if base.nil?
        api_resultpb.full_name = name
    else
        api_resultpb.base_type = base
        api_resultpb.full_name = "#{base}.#{name}"
    end
    if !args.nil?
        args.each do |arg|
            api_resultpb.arguments << arg
        end
    end
    api_resultpb.source = source_text
    start_locpb = Proto::SourceLocation.new
    start_locpb.row = source_range.line
    start_locpb.column = source_range.column
    start_locpb.file_info = filepb
    end_locpb = Proto::SourceLocation.new
    end_locpb.row = source_range.last_line
    end_locpb.column = source_range.last_column
    end_locpb.file_info = filepb
    rangepb = Proto::SourceRange.new
    rangepb.start = start_locpb
    rangepb.end = end_locpb
    api_resultpb.range = rangepb
    return api_resultpb
end



def rubyAstGen(inpath, outfile, configpb, root=nil, pkg_name=nil, pkg_version=nil)
    # Read code from file
    infiles, root = getInfiles(inpath, root)

    # initialize resultpb
    pkg = Proto::PkgAstResult.new
    pkg.config = configpb
    if !pkg_name.nil?
        pkg.pkg_name = pkg_name
    else
        pkg.pkg_name = File.basename(inpath)
    end
    if !pkg_version.nil?
        pkg.pkg_version = pkg_version
    end
    pkg.language = Proto::Language::RUBY

    # opt-in to most recent AST format:
    # https://github.com/whitequark/parser#usage
    Parser::Builders::Default.emit_lambda   = true
    Parser::Builders::Default.emit_procarg0 = true
    Parser::Builders::Default.emit_encoding = true
    Parser::Builders::Default.emit_index    = true

    infiles.each { |infile|
        puts "analyzing #{infile}"

        begin
            # AST and Source Location
            # https://github.com/whitequark/parser/blob/master/doc/AST_FORMAT.md
            # AST Visitor
            # https://github.com/whitequark/parser/issues/49
            code = File.open(infile, "r") { |f| f.read }
            parser = Parser::CurrentRuby.new
            buffer = Parser::Source::Buffer.new('(string)')
            buffer.source = code
        rescue Exception => ex
            puts "Preparation error: #{ex}"
            next
        end
        begin
            ast = parser.parse(buffer)
            # for debugging purposes, uncomment the following line to print ast
            # puts ast
        rescue Exception => ex
            puts "Parse error: #{ex}"
            next
        end
        begin
            # FIXME: sometimes the process function throws exception, not sure why
            visitor = RubyDeclRefVisitor.new(buffer, configpb)
            visitor.process(ast)
        rescue Exception => ex
            puts "Visitor error: #{ex}"
            next
        end

        filepb = getFilepb(infile, root)
        visitor.decl_refs.each do |decl_ref|
            api_resultpb = getApiResult(decl_ref['base'], decl_ref['name'],
                decl_ref['args'], decl_ref['source_text'], decl_ref['source_range'], filepb)
            pkg.api_results << api_resultpb
        end
    }

    resultpb = Proto::PkgAstResults.new
    resultpb.pkgs << pkg

    # save resultpb
    File.open(outfile, 'w') { |f| f.write(Proto::PkgAstResults.encode(resultpb)) }
end



if __FILE__ == $0
    # OptionParser
    # https://ruby-doc.org/stdlib-2.5.1/libdoc/optparse/rdoc/OptionParser.html
    # http://rubylearning.com/blog/2011/01/03/how-do-i-make-a-command-line-tool-in-ruby/

    ARGV << '-h' if ARGV.empty?

    options = {}
    OptionParser.new do |opts|
        opts.banner = "Usage: astgen.rb [options]"
        opts.on("-i", "--inpath INPATH", "Path to the input directory or file.") do |i|
            options[:inpath] = i
        end
        opts.on("-c", "--config CONFIG", "Optional path to the filter of nodes, stored in proto buffer format (AstLookupConfig in ast.proto).") do |c|
            options[:config] = c
        end
        opts.on("-o", "--outfile OUTFILE", "Path to the output file.") do |o|
            options[:outfile] = o
        end
        opts.on("-b", "--root ROOT", "Path to the root of the source.") do |b|
            options[:root] = b
        end
        opts.on("-n", "--package_name NAME", "Package name of the specified input.") do |n|
            options[:package_name] = n
        end
        opts.on("-v", "--package_version VERSION", "Package version of the specified input.") do |v|
            options[:package_version] = v
        end
        opts.on_tail("-h", "--help", "Prints this help") do
            puts opts
            exit
        end
    end.parse!

    # parse options
    inpath = options[:inpath]
    outfile = options[:outfile]
    config = options[:config]
    root = options[:root]
    pkg_name = options[:package_name]
    pkg_version = options[:package_version]

    # load config pb
    # https://stackoverflow.com/questions/130948/read-binary-file-as-string-in-ruby
    configStr = File.open(config, "rb") { |f| f.read }
    # protobuf for ruby
    # https://developers.google.com/protocol-buffers/docs/reference/ruby-generated
    configpb = Proto::AstLookupConfig.decode(configStr)

    # invoke the ast generation
    rubyAstGen(inpath, outfile, configpb, root, pkg_name, pkg_version)
end

