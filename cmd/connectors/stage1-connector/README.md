# Setup
The OST Stage1 connector runs as an OST bot in OST's bot_engine container.

The following environment variables configure the Stage1 Nemesis connecter. They can be set via stage1's docker-compose file or by hardcoding them in [nemesis_connector.py](nemesis_connector/nemesis_connector.py):
- `NEMESIS_URL` - The URI of Nemesis's API (e.g., http://10.0.0.1:8080/api/)
- `NEMESIS_USERNAME` - Username for the Nemesis API
- `NEMESIS_PASSWORD` - Password for the Nemesis API
- `NEMESIS_PROJECT` - Name of the project being worked on (e.g., ACME-CORP)
- `NEMESIS_EXPIRATION_DAYS` - Days until the data should expire and be deleted
- `NEMESIS_LOG_LEVEL` - Logging level (e.g., DEBUG/INFO)

Once the above configuration variables are set, copy `nemesis_connector.py` to `<OST_dir>/shared/bots/on/` and then restart OST's bot_engine container (`docker restart <containerId>`).