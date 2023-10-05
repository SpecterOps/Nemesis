#!/bin/bash

export CS_JAVA_OPTS="-Xmx64m"
# export CS_JAVA_CLASSPATH="/opt/cobaltstrike-nemesis-connector/SSLUtils.jar:/opt/cobaltstrike-nemesis-connector/json-java.jar"

export DATE_STR=$(date "+%Y%m%d-%H%M%S")
export CS_USER="nemesis-bot-${DATE_STR}"  # Appending date string to avoid CS's "User already connected" error

echo "Staring Nemesis Bot. Teamserver[${COBALTSTRIKE_TEAMSERVER_IP}] User[${CS_USER}]"
./agscript "$COBALTSTRIKE_TEAMSERVER_IP" "50050" "${CS_USER}" "${COBALTSTRIKE_TEAMSERVER_PASSWORD}" "/opt/cobaltstrike-nemesis-connector/nemesis-connector.cna" 2>&1 |\
while read line ; do
    echo $line

    # Workaround for agscript not exiting on Java OutOfMemory errors... :(
    if [[ $line == *'Exception in thread "TeamQueue Reader" java.lang.OutOfMemoryError'* ]]; then
        echo "Java OutOfMemory error! Killing agscript process."
        pkill -9 java
        break
    fi
done;
