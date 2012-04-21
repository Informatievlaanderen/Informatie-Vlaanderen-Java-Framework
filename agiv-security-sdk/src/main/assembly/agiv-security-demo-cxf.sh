#!/bin/bash
echo Using Apache CXF...

CXF_HOME=$HOME/apache-cxf-2.5.3
if [ ! -d $CXF_HOME ]; then
	echo "Apache CXF home not present: $CXF_HOME"
	exit 1
fi

CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
for JARFILE in $CXF_HOME/lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

java -cp $CLASSPATH be.agiv.security.demo.Main
