#!/bin/bash


if [ -z ${EXTERNALRACLI_HOME} ] ; then
	EXTERNALRACLI_HOME=`echo $(dirname ${0})`
fi

java -Djava.endorsed.dirs=${EXTERNALRACLI_HOME}/endorsed -jar $EXTERNALRACLI_HOME/externalra-cli.jar "${@}"
