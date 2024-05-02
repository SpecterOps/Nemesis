# nemesis_sync

## Usage

### Execute via Stand Alone Docker

Use Docker and `docker-compose` to run the `mythic_nemesis_sync` container.

After cloning repository, open the `settings.env` file and fill in the variables with appropriate values. The following is an example:

``` text
MYTHIC_IP=10.10.1.100
MYTHIC_PORT=7443
MYTHIC_USERNAME=mythic_admin
MYTHIC_PASSWORD=SuperSecretPassword
REDIS_HOSTNAME=redis
REDIS_PORT=6379
NEMESIS_HTTP_SERVER=https://172.16.111.187:8000
NEMESIS_CREDS=nemesis:password
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=password
MAX_FILE_SIZE=100000000
EXPIRATION_DAYS=100
```

**Note**: The `NEMESIS_CREDS` are the `username` / `password` fields in the `basic-auth` Kubernetes secret. `MAX_FILE_SIZE` is in bytes, and `EXPIRATION_DAYS` is the number of days until data will be expunged from backend storage.

**Make sure the `NEMESIS_HTTP_SERVER` and `MYTHIC_IP` variables do not reference localhost or 127.0.0.1! They need to be reachable from a Docker container.**

Once the environment variables are setup, you can launch the service by using `docker-compose`:

``` bash
sudo docker-compose up --build
```

## Troubleshooting

Logs can be seen from the docker container via `sudo docker logs mythic_nemesis_sync` and follow them with `sudo docker logs --follow mythic_nemesis_sync`.

Ensure the host where `mythic_nemesis_sync` is running has network access to the Nemesis and Mythic servers.

`mythic_nemesis_sync` uses an internal Redis database to sync what events have already been sent to Nemesis, avoiding duplicates. If the `mythic_nemesis_sync` service goes down, it *should* be safe to stand it back up - duplicates should be available long as nothing has forcefully stopped/deleted Mythic's Redis container.

## Reprocessing Data

The container uses Redis to keep a persistent store of Mythic data that's been submitted to Nemesis. If you want to reprocess data, set `CLEAR_REDIS=True` in settings.env to clear the Redis database. There will be a 30 second pause on startup with a warning message indicating aborting the standup will avoid clearing the database.

## Fixing Processing Starting Points

If the Redis database is wiped and you don't want to reprocess all existing data again, you can set the Mythic ID starting points (0 being starting from the beginning, i.e. reprocessing) for syncing of files, file listings, and processes by adding the following to settings.env:

```
REDIS_LAST_FILE_ID=123
REDIS_LAST_FILEBROWSER_ID=456
REDIS_LAST_PROCESS_ID=789
```

You can find the last processed file ID through Hasura (https://MYTHIC/console/, using the HASURA_SECRET from Mythic's .env file) with:

```
query MyQuery {
  filemeta(order_by: {id: desc}, limit: 1, where: {is_download_from_agent: {_eq: true}, complete: {_eq: true}, is_screenshot: {_eq: false}}) {
    id
  }
}
```

You can find the last processed file listing ID through Hasura (https://MYTHIC/console/, using the HASURA_SECRET from Mythic's .env file) with:

```
query MyQuery {
  mythictree(order_by: {id: desc}, limit: 1, where: {tree_type: {_eq: "file"}}) {
    id
  }
}
```

You can find the last processed processing listing ID through Hasura (https://MYTHIC/console/, using the HASURA_SECRET from Mythic's .env file) with:

```
query MyQuery {
  mythictree(order_by: {id: desc}, limit: 1, where: {tree_type: {_eq: "process"}}) {
    id
  }
}
```

## References

- [Mythic](https://github.com/its-a-feature/Mythic) - Multi-platform C2 Framework
