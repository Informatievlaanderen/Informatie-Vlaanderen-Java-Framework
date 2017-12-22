#!/bin/bash
echo Using Metro...

METRO_HOME=$HOME/metro
if [ ! -d $METRO_HOME ]; then
	echo "Metro home not present: $METRO_HOME"
	exit 1
fi

CLASSPATH=../informatievlaanderen-security-client-${project.version}.jar:informatievlaanderen-security-demo-${project.version}.jar
for JARFILE in $METRO_HOME/lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

java -cp $CLASSPATH be.vlaanderen.informatievlaanderen.security.demo.Main
