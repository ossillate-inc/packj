#!/bin/bash

rm -r java cpp python php ruby javascript
mkdir java cpp python php ruby javascript
touch python/__init__.py
protoc --proto_path=./ --python_out=python/ --cpp_out=cpp/ --java_out=java/ --php_out=php/ --ruby_out=ruby/ --js_out=import_style=commonjs,binary:javascript/ *.proto

# FIXME: this is hacky! need a robust path and clean up operation!
cp -r java/* ../static_proxy/astgen-java/src/main/java/

# FIXME: this is hacky too! proto files are placed under global namespace and may have conflict with each other!
rm ../static_proxy/brakeman/lib/*_pb.rb && cp -r ruby/* ../static_proxy/brakeman/lib/
rm -r ../static_proxy/progpilot/package/src/progpilot/php/* && cp -r php/* ../static_proxy/progpilot/package/src/progpilot/php/
cp -r java/* ../static_proxy/flowdroid/soot-infoflow/src/
# TODO: java and javascript files may need to localized as well.
