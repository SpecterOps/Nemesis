# Overview of submit_to_nemesis
`submit_to_nemesis` is a CLI tool used to upload files to Nemesis. Its targeted audience is operators who want to upload files using the CLI and Nemesis developers who want to quickly test sample files.

# Docker

If you want to use the pre-build Docker container to submit artifacts to Nemesis, run [monitor_folder_docker.sh](https://github.com/SpecterOps/Nemesis/blob/main/scripts/monitor_folder_docker.sh). The only requirement for the script is Docker and wget.

# Requirements
Install with the instructions below.

<details>
<summary>
Python, Pyenv, and Poetry
</summary>
To get Nemesis running, Python 3.11.2 is needed, as well as Pyenv/Poetry.

## Install Pyenv
**Purpose:** Manages python environments in a sane way.

1. Install the [relevant prereqs specified by PyEnv](https://github.com/pyenv/pyenv/wiki#suggested-build-environment).

For Debian, this is:
```bash
sudo apt update; sudo apt install build-essential libssl-dev zlib1g-dev \
libbz2-dev libreadline-dev libsqlite3-dev curl \
libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev
```
2. Installation:
```bash
curl https://pyenv.run | bash
```
3. After running the install script, add the following to `~/.bashrc` (after pyenv finishes installing, it prints a message telling you to add this):
```bash
export PYENV_ROOT="$HOME/.pyenv"
command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```
4. Restart your shell
5. Install a version of Python and configure the version of Python to use globally on your machine
```bash
 pyenv install 3.11.2
 pyenv global 3.11.2
```

**Validation:** Running `python3 --version` should show version 3.11.2.

## Install Poetry
**Purpose:** Python package and dependency management tool.
```bash
python3 -c 'from urllib.request import urlopen; print(urlopen("https://install.python-poetry.org").read().decode())' | python3 -
```

Add the following to `~/.bashrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Restart your shell.

**Validation:** Running `poetry --version` from the shell should output the current version.

## Install Poetry Environment for Artifact Submission
**Purpose:** Install the Poetry environment for ./scripts/submit_to_nemesis.sh

`./scripts/submit_to_nemesis.sh` uses code from a Nemesis module that needs its Poetry environment installed first.

```
poetry -C ./cmd/enrichment/ install
```
</details>

# Configuring
To use `submit_to_nemesis`, one must edit the YAML configuration file found in `cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml` ([link to YAML file](https://github.com/SpecterOps/Nemesis/blob/main/cmd/enrichment/enrichment/cli/submit_to_nemesis/submit_to_nemesis.yaml)). This config file includes the credentials to authenticate to Nemesis, the location of the Nemesis server, and information about the operation that Nemesis will tag each uploaded file with (operator name, project, network, etc.).

# Usage
Once configured, in the root Nemesis directory run
 ```
 ./scripts/submit_to_nemesis.sh -h
 ```
 to execute `submit_to_nemesis` and view its help.

***Note: On the first run of the script Poetry will install all needed dependencies.***

Below are some example usage scenarios:
* Submit all files in a folder:
```
./scripts/submit_to_nemesis.sh --folder ./sample_files/
```

* Submit multiple individual files with debug logging:
```
./scripts/submit_to_nemesis.sh -f /etc/issue /etc/hosts --log_level DEBUG
```

* Monitor a folder for new files and automatically submit them to Nemesis:
```
./scripts/submit_to_nemesis.sh --monitor /path/to/folder/
```

* Stress test the Nemesis installation by submitting a folder of files 100 times with 30 workers:
```
./scripts/submit_to_nemesis.sh --folder sample_files/ -w 30 -r 100
```
