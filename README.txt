README for GeoSecure Java Security Framework Project
===============================================

=== 1. Introduction

This project contains the source code tree of the GeoSecure Java Security Framework.
The source code is hosted at: https://github.com/Informatievlaanderen/GeoSecure-Java-Framework


=== 2. Requirements

The following is required for compiling the GeoSecure Java Security Framework.
* Oracle Java 1.7.0_45
* Apache Maven 3.1.1


=== 3. Compilation

Compile the project via:
	mvn clean install
This will generate the SDK ZIP package.

You might receive an OutOfMemoryException from Maven. Prevent this via:
	export MAVEN_OPTS="-Xmx512m -XX:MaxPermSize=256m"


=== 4. Integration tests

The integration tests are located under the agiv-security-tests directory.
The integration tests require different AGIV credentials.
These credentials can be configured via:
	agiv-security-tests/src/main/resources/agiv.properties


=== 5. License

The source code of the GeoSecure Java Security Framework is licensed under the GNU
LGPL version 3.0. For more information, check out the LICENSE.txt file.
