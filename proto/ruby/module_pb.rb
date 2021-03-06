# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: module.proto

require 'google/protobuf'

require 'ast_pb'
require 'info_pb'
Google::Protobuf::DescriptorPool.generated_pool.build do
  add_message "proto.ModuleSource" do
    optional :node, :message, 1, "proto.AstNode"
    repeated :reachable_sources, :message, 2, "proto.AstNode"
  end
  add_message "proto.ModuleSink" do
    optional :node, :message, 1, "proto.AstNode"
    repeated :reachable_sinks, :message, 2, "proto.AstNode"
  end
  add_message "proto.ModuleTaintWrapper" do
    optional :node, :message, 1, "proto.AstNode"
    repeated :rules, :message, 2, "proto.ModuleTaintWrapper.TaintRule"
  end
  add_message "proto.ModuleTaintWrapper.TaintPoint" do
    optional :id, :int32, 1
    repeated :access_paths, :string, 2
  end
  add_message "proto.ModuleTaintWrapper.TaintRule" do
    optional :cause, :message, 1, "proto.ModuleTaintWrapper.TaintPoint"
    repeated :effects, :message, 2, "proto.ModuleTaintWrapper.TaintPoint"
  end
  add_message "proto.ModuleFlow" do
    optional :source, :message, 1, "proto.AstNode"
    repeated :hops, :message, 2, "proto.AstNode"
    optional :sink, :message, 3, "proto.AstNode"
    optional :info, :message, 4, "proto.ModuleFlow.FlowInfo"
  end
  add_message "proto.ModuleFlow.FlowInfo" do
    optional :name, :string, 1
    optional :cwe, :string, 2
    optional :type, :string, 3
  end
  add_message "proto.ModuleDanger" do
    optional :danger, :message, 1, "proto.AstNode"
    repeated :slices, :message, 2, "proto.AstNode"
  end
  add_message "proto.ModuleSummary" do
    optional :package_info, :message, 1, "proto.PackageInfo"
    repeated :sources, :message, 2, "proto.ModuleSource"
    repeated :sinks, :message, 3, "proto.ModuleSink"
    repeated :taint_wrappers, :message, 4, "proto.ModuleTaintWrapper"
  end
  add_message "proto.ModuleResult" do
    optional :package_info, :message, 1, "proto.PackageInfo"
    repeated :flows, :message, 2, "proto.ModuleFlow"
    repeated :dangers, :message, 3, "proto.ModuleDanger"
  end
  add_message "proto.ModuleStatic" do
    optional :package_info, :message, 1, "proto.PackageInfo"
    repeated :flows, :message, 2, "proto.ModuleFlow"
    repeated :dangers, :message, 3, "proto.ModuleDanger"
    repeated :sources, :message, 4, "proto.ModuleSource"
    repeated :sinks, :message, 5, "proto.ModuleSink"
    repeated :taint_wrappers, :message, 6, "proto.ModuleTaintWrapper"
  end
end

module Proto
  ModuleSource = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleSource").msgclass
  ModuleSink = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleSink").msgclass
  ModuleTaintWrapper = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleTaintWrapper").msgclass
  ModuleTaintWrapper::TaintPoint = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleTaintWrapper.TaintPoint").msgclass
  ModuleTaintWrapper::TaintRule = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleTaintWrapper.TaintRule").msgclass
  ModuleFlow = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleFlow").msgclass
  ModuleFlow::FlowInfo = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleFlow.FlowInfo").msgclass
  ModuleDanger = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleDanger").msgclass
  ModuleSummary = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleSummary").msgclass
  ModuleResult = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleResult").msgclass
  ModuleStatic = Google::Protobuf::DescriptorPool.generated_pool.lookup("proto.ModuleStatic").msgclass
end
