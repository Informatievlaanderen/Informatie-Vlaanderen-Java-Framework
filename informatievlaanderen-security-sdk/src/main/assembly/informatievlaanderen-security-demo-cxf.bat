@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION
ECHO Apache CXF test...
SET CXF_HOME=%HOMEPATH%\apache-cxf-2.7.4
SET CLASSPATH=..\informatievlaanderen-security-client-${project.version}.jar;informatievlaanderen-security-demo-${project.version}.jar

FOR %%F IN ("%CXF_HOME%\lib\*.jar") DO (
	SET CLASSPATH=!CLASSPATH!;"%%F"
)

FOR %%F IN ("..\lib\*.jar") DO (
	SET CLASSPATH=!CLASSPATH!;%%F
)

java -cp %CLASSPATH% be.vlaanderen.informatievlaanderen.security.demo.Main