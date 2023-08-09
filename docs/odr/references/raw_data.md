# Raw Data
Date type: `raw_data`
Scope: Project

## Overview
Data that may consist of anything. Developers and operators may use this type to push arbitrary data to the ODS to take advantage of any builtin or custom automated post processing the ODS performs. Example use cases include daily status reports, C2 logs, and other data that may be unique to the workflow of a team.

| Parameters | Format      | Description                                        |
|------------|-------------|----------------------------------------------------|
| tags       | string[]    | Array of user defined case insensitive keywords    |
| is_file    | bool        | True if data is a reference to a binary submission |
| data       | string/UUID | Case sensitive data or a Nemesis UUID reference    |

## Protobuf Definition

**RawDataIngestionMessage** and **RawDataIngestion** in *nemesis.proto*

## Examples

JSON:
```json
{
	"data": [
		{
			"tags": [
				"seatbelt_json"
			],
			"data": "123777d8-7186-4063-8456-362c50a9b3db"
		}
	]
    "metadata": {
        "agent_id": "339429212",
        "agent_type": "beacon",
        "automated": 1,
        "data_type": "raw_data",
        "expiration": "2023-08-01T22:51:35",
        "project": "ASSESS-X",
        "timestamp": "2022-08-01T22:51:35"
    }
}
```