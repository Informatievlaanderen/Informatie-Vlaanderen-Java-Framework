README for AGIV Java Security Framework Project
===============================================

=== 1. Introduction

This project contains the source code tree of the AGIV Java Security Framework.
The source code is hosted at: http://code.google.com/p/agiv-security/


=== 2. Requirements

The following is required for compiling the AGIV Java Security Framework.
* Oracle Java 1.7.0_06
* Apache Maven 3.0.4


=== 3. Compilation

Compile the project via:
	mvn clean install
This will generate the SDK ZIP package.


=== 4. Integration tests

The integration tests are located under the agiv-security-tests directory.
The integration tests require different AGIV credentials.
These credentials can be configured via:
	agiv-security-tests/src/main/resources/agiv.properties


=== 5. License

The source code of the AGIV Java Security Framework is licensed under the GNU
LGPL version 3.0. For more information, check out the LICENSE.txt file.
