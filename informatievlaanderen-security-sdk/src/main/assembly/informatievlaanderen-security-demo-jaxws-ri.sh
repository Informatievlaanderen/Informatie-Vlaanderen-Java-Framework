#!/bin/bash
echo Using JAX-WS RI...

JAXWS_RI_HOME=$HOME/jaxws-ri
if [ ! -d $JAXWS_RI_HOME ]; then
	echo "JAX-WS RI home not present: $JAXWS_RI_HOME"
	exit 1
fi

CLASSPATH=../informatievlaanderen-security-client-${project.version}.jar:informatievlaanderen-security-demo-${project.version}.jar
for JARFILE in $JAXWS_RI_HOME/lib/*.jar
do
    CLASSPATH=$CLASSPATH:$JARFILE
done
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

java -cp $CLASSPATH be.vlaanderen.informatievlaanderen.security.demo.Main
