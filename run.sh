#!/bin/bash

BIN=bin
LIB=lib
PROPS=props

CP=$BIN

for JAR_FILE in "$LIB"/*.jar; do
  CP="$CP:$JAR_FILE"
done

java \
  -Djava.util.logging.config.file=$PROPS/logging.properties \
  -cp $CP \
  pia4java.PiaManager \
  $PROPS/config.txt \
  $@

