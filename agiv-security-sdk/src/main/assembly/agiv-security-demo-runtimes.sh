#!/bin/bash
echo "AGIV Java Security JAX-WS runtime tests..."

function JAXWS_RI_ {
	echo "	JAX-WS RI $1 test"
	JAXWS_RI_HOME=$HOME/jaxws-ri-$1
	CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
	for JARFILE in $JAXWS_RI_HOME/lib/*.jar
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	for JARFILE in ../lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	java -cp $CLASSPATH be.agiv.security.demo.CLIMain $2 $3 $4 $5 > /dev/null 2>&1
	echo "		$?"
}

function JAXWS_RI_21 {
	JAXWS_RI_ "2.1.7" $1 $2 $3 $4
	JAXWS_RI_ "2.1.9" $1 $2 $3 $4
}

function JAXWS_RI_22 {
	JAXWS_RI_ "2.2.5" $1 $2 $3 $4
	JAXWS_RI_ "2.2.6" $1 $2 $3 $4
	JAXWS_RI_ "2.2.6-2" $1 $2 $3 $4
	JAXWS_RI_ "2.2.6-3" $1 $2 $3 $4
	JAXWS_RI_ "2.2.7" $1 $2 $3 $4
}

function JAXWS_DEFAULT {
	echo "	JAX-WS default test"
	CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
	for JARFILE in ../lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	java -cp $CLASSPATH be.agiv.security.demo.CLIMain $1 $2 $3 $4 > /dev/null 2>&1
	echo "		$?"
}

function CXF_ {
	echo "	Apache CXF $1 test"
	CXF_HOME=$HOME/apache-cxf-$1
	CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
	for JARFILE in $CXF_HOME/lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	for JARFILE in ../lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	java -cp $CLASSPATH be.agiv.security.demo.CLIMain $2 $3 $4 $5 > /dev/null 2>&1
	echo "		$?"
}

function CXF_23 {
	CXF_ "2.3.9" $1 $2 $3 $4
	CXF_ "2.3.10" $1 $2 $3 $4
	CXF_ "2.3.11" $1 $2 $3 $4
}

function CXF_24 {
	CXF_ "2.4.6" $1 $2 $3 $4
	CXF_ "2.4.7" $1 $2 $3 $4
	CXF_ "2.4.8" $1 $2 $3 $4
	CXF_ "2.4.9" $1 $2 $3 $4
	CXF_ "2.4.10" $1 $2 $3 $4
}

function CXF_25 {
	CXF_ "2.5.2" $1 $2 $3 $4
	CXF_ "2.5.3" $1 $2 $3 $4
	CXF_ "2.5.4" $1 $2 $3 $4
	CXF_ "2.5.5" $1 $2 $3 $4
	CXF_ "2.5.6" $1 $2 $3 $4
	CXF_ "2.5.7" $1 $2 $3 $4
	CXF_ "2.5.8" $1 $2 $3 $4
	CXF_ "2.5.9" $1 $2 $3 $4
	CXF_ "2.5.10" $1 $2 $3 $4
}

function CXF_26 {
	CXF_ "2.6.0" $1 $2 $3 $4
	CXF_ "2.6.1" $1 $2 $3 $4
	CXF_ "2.6.2" $1 $2 $3 $4
	CXF_ "2.6.3" $1 $2 $3 $4
	CXF_ "2.6.4" $1 $2 $3 $4
	CXF_ "2.6.5" $1 $2 $3 $4
	CXF_ "2.6.6" $1 $2 $3 $4
}

function CXF_27 {
	CXF_ "2.7.0" $1 $2 $3 $4
	CXF_ "2.7.1" $1 $2 $3 $4
	CXF_ "2.7.2" $1 $2 $3 $4
	CXF_ "2.7.3" $1 $2 $3 $4
	CXF_ "2.7.4" $1 $2 $3 $4
}

function METRO_ {
	echo "	Metro $1 test"
	METRO_HOME=$HOME/metro-$1
	CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
	for JARFILE in $METRO_HOME/lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	for JARFILE in ../lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done
	java -cp $CLASSPATH be.agiv.security.demo.CLIMain $2 $3 $4 $5 > /dev/null 2>&1
	echo "		$?"
}

function METRO_21 {
	METRO_ "2.1.1" $1 $2 $3 $4
}

function METRO_22 {
	METRO_ "2.2" $1 $2 $3 $4
	METRO_ "2.2.0-1" $1 $2 $3 $4
	METRO_ "2.2.0-2" $1 $2 $3 $4
	METRO_ "2.2.1" $1 $2 $3 $4
	METRO_ "2.2.1-1" $1 $2 $3 $4
}

function AXIS2_ {
	echo "	Axis2 $1 test"
	AXIS2_HOME=$HOME/axis2-$1
	CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
	for JARFILE in ../lib/*
	do
	    CLASSPATH=$CLASSPATH:$JARFILE
	done

	$AXIS2_HOME/bin/axis2.sh -cp $CLASSPATH be.agiv.security.demo.CLIMain $2 $3 $4 $5 > /dev/null 2>&1
	echo "		$?"
}

function AXIS2 {
	AXIS2_ "1.6.1" $1 $2 $3 $4
	AXIS2_ "1.6.2" $1 $2 $3 $4
}

function JAXWS_TESTS {
	JAXWS_DEFAULT $1 $2 $3 $4
	JAXWS_RI_21 $1 $2 $3 $4
	JAXWS_RI_22 $1 $2 $3 $4
	CXF_23 $1 $2 $3 $4
	CXF_24 $1 $2 $3 $4
	CXF_25 $1 $2 $3 $4
	CXF_26 $1 $2 $3 $4
	CXF_27 $1 $2 $3 $4
	METRO_21 $1 $2 $3 $4
	METRO_22 $1 $2 $3 $4
	AXIS2 $1 $2 $3 $4
}

echo "Java 1.5 tests"
export JAVA_HOME=$HOME/jdk1.5.0_22
export PATH=$JAVA_HOME/bin:$PATH
java -version

JAXWS_TESTS $1 $2 $3 $4

echo "Java 1.6 tests"
export JAVA_HOME=$HOME/jdk1.6.0_45
export PATH=$JAVA_HOME/bin:$PATH
java -version

JAXWS_TESTS $1 $2 $3 $4

echo "Java 1.7 tests"
export JAVA_HOME=$HOME/jdk1.7.0_21
export PATH=$JAVA_HOME/bin:$PATH
java -version

JAXWS_TESTS $1 $2 $3 $4


