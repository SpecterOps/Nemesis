# Ingesting a New Seatbelt Datatype

*Note: for each file mentioned, search for "named_pipe" or "namedpipe" to see an example values for what to do.*

1. Generate a sample .ndjson output file for the module from Seatbelt for testing.
2. In `./cmd/enrichment/enrichment/tasks/raw_data_tag/seatbelt_datatypes.py`:
    - In *SeatbeltDtoTypes* at the top add in a maping for the "Seatbelt.Commands.Windows.\<DATA_TYPE\>" output.
    - Create a new *Seatbelt\<DATA_TYPE\>* dataclass with case sensitive fields that match the Seatbelt data type.
        - Implement *from_dict()* and *to_protobuf()* functions and include any additional mapping/processing for specific fields needed.
3. In `./cmd/enrichment/enrichment/containers.py`:
    - In the *Container* class add a *outputq_\<DATA_TYPE\>* similar to the surrounding examples and ensure it's sorted alphabetically.
    - In *task_rawdatatag()* add the new queue as an argument.
4. In `./cmd/enrichment/enrichment/tasks/raw_data_tag/raw_data_tag.py`:
    - Add a *MessageQueueProducerInterface* for the datatype in the init sections, ensuring the argument position matches what you specified in *containers.py*.
    - In *process_seatbelt_raw_data()* pass the new queue to *seatbelt_json()*
5. In `./cmd/enrichment/enrichment/tasks/raw_data_tag/seatbelt_json.py`:
    - Import the new *Seatbelt\<DATA_TYPE\>* dataclass in the *from enrichment.tasks.raw_data_tag.seatbelt_datatypes* section at the top of the file.
    - Add a *MessageQueueProducerInterface* for the datatype in the init sections, ensuring the argument position matches what you specified in *raw_data_tag.py*.
    - In *process_dto()*, add a new `elif obj.Type == SeatbeltDtoTypes.<DATA_TYPE\>.value:` section to handle processing.
        - See the nearby *SeatbeltDtoTypes.NAMED_PIPE.value* example if emitting a *<DATA_TYPE\>IngestionMessage* protobuf.
        - See the *SeatbeltDtoTypes.SLACK_DOWNLOADS.value* example if shoving data straight into Postgres.
