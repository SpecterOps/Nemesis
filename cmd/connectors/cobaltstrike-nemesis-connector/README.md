Aggressor project that ingests Cobalt Strike data into Nemesis.

The project can be run on a teamserver to ingest data tasks by ALL clients, or can be run on an individual client instance to ingest data just from that client.

Also contains the `bof_reg_collect` , a Beacon Object File to collect registry data in a serialized manner.

# Usage
Make sure the following environment variables are set before running `nemesis-connector.cna`:

| Configuration Variable             | Required | Example                     | Default (if applicable) | Description                                                                                                   |
|------------------------------------|----------|-----------------------------|-------------------------|---------------------------------------------------------------------------------------------------------------|
| NEMESIS_COBALTSTRIKE_DOWNLOADS_DIR | Yes      | /tmp/                       |                         | Temporary directory used when syncing downloads from a Cobalt Strike teamserver                               |
| NEMESIS_BASE_URL                   | Yes      | http://192.168.230.42:8080/ |                         | Base URL used when constructing the URL to web api, elastic, kibana, etc (e.g., NEMESIS_BASE_URL + "/kibana") |
| NEMESIS_CREDS                      | Yes      | nemesis:Qwerty12345         |                         | Basic auth credentials used when accessing the Nemesis frontend web endpoints                                 |
| NEMESIS_DEBUG_JSON                 | No       | 1                           | 0                       | Print JSON responses from web API requests                                                                    |
| NEMESIS_PROJECT                    | Yes      | ASSESS-123                  |                         | Assessmend project ID the teamserver is associated with                                                       |
| NEMESIS_DATA_EXPIRATION_DAYS       | Yes      | 100                         | 100                     | Number of days after which Nemesis should expire the data                                                     |

Example:
```
export NEMESIS_COBALTSTRIKE_DOWNLOADS_DIR=/tmp/
export NEMESIS_BASE_URL=http://192.168.230.100:8080/
export NEMESIS_CREDS="nemesis:Qwerty12345"
# export NEMESIS_DEBUG_JSON="1"
export NEMESIS_PROJECT=ASSESS-X
export NEMESIS_DATA_EXPIRATION_DAYS=100
```

When launching the Cobalt Strike GUI or `agscript`, ensure that `SSLUtils.jar` is added to the classpath, e.g. for `agscript`:

```
...

java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -classpath "${CSJAR}:/home/user/Toolkit/cobaltstrike-nemesis-connector/SSLUtils.jar" aggressor.headless.Start $*

```

Then, load `nemesis-connector.cna` using agscript or into the Cobalt Stike client GUI:

```
./agscript <IP> 50050 nemesis-bot Password123! /home/user/Toolkit/cobaltstrike-nemesis-connector/nemesis-connector.cna
```

**Note:** the `agscript` command can be run from the teamserver itself, or any other server with Cobalt Strike installed.


## Interacting with nemesis-bot

Communication from the client to the `nemesis-bot` on the server occurs through the event log. In order to interact with `nemesis-bot`, go to `Cobalt Strike` -> `Script Console` and use the privmsg() function. All current interaction commands are listed below.

To trigger reprocessing of all downloads:

    aggressor> x privmsg("nemesis-bot", "ReprocessDownloads")
