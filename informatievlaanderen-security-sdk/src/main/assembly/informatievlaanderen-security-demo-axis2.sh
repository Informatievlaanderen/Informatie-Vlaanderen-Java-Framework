#!/bin/bash
echo Using Apache Axis2...

AXIS2_HOME=$HOME/axis2-1.6.1
if [ ! -d $AXIS2_HOME ]; then
	echo "Apache Axis2 home not present: $AXIS2_HOME"
	exit 1
fi

CLASSPATH=../informatievlaanderen-security-client-${project.version}.jar:informatievlaanderen-security-demo-${project.version}.jar
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

$AXIS2_HOME/bin/axis2.sh -cp $CLASSPATH be.vlaanderen.informatievlaanderen.security.demo.Main
