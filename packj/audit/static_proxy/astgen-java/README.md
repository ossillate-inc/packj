# HowTo #

- Build the project
	- `mvn clean compile assembly:single`
- Run the program
    - `java -jar target/astgen-java-1.0.0-jar-with-dependencies.jar -help`
    - `java -jar target/astgen-java-1.0.0-jar-with-dependencies.jar -inpath ../../../testdata/struts2-core-2.3.31.jar -outfile ../../../testdata/struts2-core-2.3.31.jar.out -config ../../../config/test_astgen_java.config -sig_outfile ../../../testdata/struts2-core-2.3.31.jar.sig`
    - `java -jar target/astgen-java-1.0.0-jar-with-dependencies.jar -android_jar_dir platforms/ -config ../../../config/test_astgen_java.config -inpath testdata/ServerSocket.pii_flow.v3.apk -intype APK -outfile testdata/ServerSocket.pii_flow.v3.apk.out -sig_outfile testdata/ServerSocket.pii_flow.v3.apk.sig`


# TODO #

- Add support for AAR format
- Update Pscout data for new android platforms
    - [PScout Android permission mappings](https://github.com/zyrikby/PScout)
    - [Mirror of PScout (http://pscout.csl.toronto.edu/).](https://github.com/dweinstein/pscout)
    - [This site hosts versions of the Pscout Android Permission Mapping tool.](https://security.csl.toronto.edu/pscout/)
    - [axplorer - Android Permission Mappings](https://github.com/reddr/axplorer)


# Links #

[Create an executable jar with dependencies using maven](https://stackoverflow.com/questions/574594/how-can-i-create-an-executable-jar-with-dependencies-using-maven)
[PScout Android Permission Mapping tool](https://security.csl.toronto.edu/pscout/)
[axplorer - Android Permission Mappings](https://github.com/reddr/axplorer)
[Latest version of M2Eclipse](http://www.eclipse.org/m2e/)

