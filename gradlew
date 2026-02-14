#!/bin/sh
#
# Gradle start up script for POSIX (macOS, Linux)
# Usage: ./gradlew [tasks]
#
set -e

APP_HOME=$( cd -P "$( dirname "$0" )" >/dev/null && pwd )
CLASSPATH="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
JAVACMD="${JAVA_HOME:-}/bin/java"
[ -z "$JAVA_HOME" ] && JAVACMD="java"

exec "$JAVACMD" -Dorg.gradle.appname=gradlew -Dfile.encoding=UTF-8 -Xmx64m -Xms64m -classpath "$CLASSPATH" org.gradle.wrapper.GradleWrapperMain "$@"
