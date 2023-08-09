# Creating a ODR Data Type

*Note: for each file mentioned, search for "named_pipe" or "namedpipe" to see an example values for what to do.*

1. Build out the fields for the new new datatype at `./docs/odr/references/\<DATA_TYPE\>.md`
2. Create a sample structured json input in `./sample_files/structured/\<DATA_TYPE\>.json`
    - In `./cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.py` add a handler at the top of the *process_file()* function.
3. Build a new **\<DATA_TYPE\>Ingestion** and **\<DATA_TYPE\>IngestionMessage** protbuf definitions in nemesis.proto
4. In `./cmd/enrichment/enrichment/services/web_api/service.py` add in the data type name to protobuf mapping in MAP at the top of the file.
5. In `./packages/python/nemesiscommon/nemesiscommon/constants.py` create a new **Q_\<DATA_TYPE\>** queue and add it to the ALL_QUEUES list.
    - If there will be intial and processed versions of the data type, also create a **Q_\<DATA_TYPE\>_PROCESSED** queue and add it to the ALL_QUEUES list.
6. If the ODR should ingest into Elasticsearch:
    1. Create a new **ES_INDEX_\<DATA_TYPE\>** in in Elastic index section in `./packages/python/nemesiscommon/nemesiscommon/constants.py`
    2. In `./cmd/enrichment/enrichment/tasks/elastic_connector.py`:
        - Add **\<DATA_TYPE\>_queue** to the init section
        - Create a **send_\<DATA_TYPE\>()** function and add the call to the **tasks** list in run().
    43. In `./cmd/enrichment/enrichment/containers.py`:
        - In the *Container* class add a *inputq_\<DATA_TYPE\>_elasticconnector* similar to the surrounding examples.
        - In *task_elasticconnector()* add the new queue as an argument.
7. If the ODR should ingest into Postgres:
    1. In `./kubernetes/postgres/configmap.yaml` create the appropriate table.
        - Start up the infra and navigate to the tables in Postgres to ensure everything created correctly (an error will prevent everything from being created).
    2. In `./cmd/enrichment/enrichment/lib/nemesis_db.py`:
        - Create a new dataclass at the top of the file for your object to store in Postgres.
        - In the *NemesisDbInterface* class create a new *add_\<DATA_TYPE\>_object()* abstract method that accepts the new dataclass.
        - In the *NemesisDb* class implement the *add_\<DATA_TYPE\>_object()* method similiar to the surrounding examples.
    3. In `./cmd/enrichment/enrichment/tasks/postgres_connector/postgres_connector.py`:
        - Import the new dataclass in the *from enrichment.lib.nemesis_db import* section at the top of the file.
        - Add a new *\<DATA_TYPE\>_q* MessageQueueConsumerInterface to the init sections of the *PostgresConnector* class, ensuring the argument position matches what you specified in *containers.py*.
        - In *run()*, add a `self.\<DATA_TYPE\>_q.Read(self.process_\<DATA_TYPE\>),  # type: ignore` line to the asyncio.gather section.
        - Implement a *process_\<DATA_TYPE\>()* function (see *process_named_pipe()* for a simple example).
    4. In `./cmd/enrichment/enrichment/containers.py`:
        - In the *Container* class add a *inputq_\<DATA_TYPE\>_postgresconnector* similar to the surrounding examples.
        - In *task_postgresconnector()* add the new queue as an argument.
