# Sliver Connector

## Getting Started
1. Get Sliver configuration

```
cat ~/.sliver-client/configs/<your config>.cfg
```

2. Configure settings.env with Sliver settings

```
SLIVER_OPERATOR="..."
SLIVER_LHOST="..."
SLIVER_LPORT=31337
SLIVER_CA_CERT="..."
SLIVER_PRIVATE_KEY="..."
SLIVER_CERT="..."
SLIVER_TOKEN="..."
```

3. Configure settings.env with Nemesis settings

```
NEMESIS_HTTP_SERVER=http://127.0.0.1
NEMESIS_CREDS=nemesis:password
```

4. Install dependencies

```
pip3 install -r requirements.txt
```

5. Start `sliver_service`

```
python3 -m sliver_service
```


## Troubleshooting

- If you experience SSL errors, you'll need to install grpcio with the following command:

```
pip3 install -U grpcio==1.37 --force --no-binary=grpcio
```

For reference, see [here](https://github.com/moloch--/sliver-py#kali-linux--fix-openssl-errors) and [here](https://github.com/grpc/grpc/issues/24252#issuecomment-823092600)

# TODO

- See if you can pull agent ID. Doesn't seem possible from RPC endpoint
- Try to collect usernames/passwords