# Setup
The OST Stage1 connector runs as an OST bot (refer to their installation instructions for where to put the python file).

The following environment variables configure the container:
- `NEMESIS_URL` - The URI of Nemesis's API (e.g., http://10.0.0.1:8080/api/)
- `NEMESIS_USERNAME` - Username for the Nemesis API
- `NEMESIS_PASSWORD` - Password for the Nemesis API
- `NEMESIS_PROJECT` - Name of the project being worked on (e.g., ACME-CORP)
- `NEMESIS_EXPIRATION_DAYS` - Days until the data should expire and be deleted
- `NEMESIS_LOG_LEVEL` - Logging level (e.g., DEBUG/INFO)

These can be set via stage1's docker-compose file or by hardcoding them in [nemesis_connector.py](nemesis_connector/nemesis_connector.py)