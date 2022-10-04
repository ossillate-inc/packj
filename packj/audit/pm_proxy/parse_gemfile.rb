#require 'rubygems'
require 'bundler'

parser = Bundler::LockfileParser.new(Bundler.read_file(ARGV[0]))
#parser.specs.each { |name, version| puts name; puts version }
parser.specs.each { |name| puts name; }
