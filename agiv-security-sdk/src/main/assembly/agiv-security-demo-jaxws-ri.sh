#!/bin/bash
echo Using JAX-WS RI...

JAXWS_RI_HOME=$HOME/jaxws-ri
if [ ! -d $JAXWS_RI_HOME ]; then
	echo "JAX-WS RI home not present: $JAXWS_RI_HOME"
	exit 1
fi

CLASSPATH=../agiv-security-client-${project.version}.jar:agiv-security-demo-${project.version}.jar
for JARFILE in $JAXWS_RI_HOME/lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done
for JARFILE in ../lib/*
do
    CLASSPATH=$CLASSPATH:$JARFILE
done

java -cp $CLASSPATH be.agiv.security.demo.Main
