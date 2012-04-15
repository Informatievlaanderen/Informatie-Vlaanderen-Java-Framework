#!/bin/bash
echo Using Apache Axis2...

AXIS2_HOME=$HOME/axis2-1.6.1
if [ ! -d $AXIS2_HOME ]; then
	echo "Apache Axis2 home not present: $AXIS2_HOME"
	exit 1
fi

CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

$AXIS2_HOME/bin/axis2.sh -cp $CLASSPATH be.agiv.security.demo.Main
