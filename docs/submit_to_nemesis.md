# Overview of submit_to_nemesis
`submit_to_nemesis` is a CLI tool used to upload files to Nemesis. Its targeted audience is operators who want to upload files using the CLI and Nemesis developers who want to quickly test sample files.

# Requirements
Ensure Python and Poetry are installed, as explained in the [requirements document](./requirements.md).

# Configuring
To use `submit_to_nemesis`, one must edit the YAML configuration file found in `cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml` ([link to YAML file](../cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml)). This config file includes the credentials to authenticate to Nemesis, the location of the Nemesis server, and information about the operation that Nemesis will tag each uploaded file with (operator name, project, network, etc.).

# Usage
Once configured, in the root Nemesis directory run the `./scripts/submit_to_nemesis.sh -h` script to execute `submit_to_nemesis` and view its help.

***Note: On the first run of the script Poetry will install install all needed dependencies.***

Below are some example usage scenarios:
* Submit all files in a folder
```
./scripts/submit_to_nemesis.sh --folder ./sample_files:
```

* Submit multiple individual files with debug logging:
```
./scripts/submit_to_nemesis.sh -f /etc/issue /etc/hosts --log_level DEBUG
```

* Monitor a folder for new files and automatically submit them to Nemesis:
```
./scripts/submit_to_nemesis.sh --monitor /path/to/folder/
```