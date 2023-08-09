# Installation

Copy:
  * `./plugins/nemesis.rb` to `/<msf-base>/plugins/nemssis.rb`
  * `./modules/nemesis.rb` to `/<msf-base>/modules/post/windows/gather/nemesis.rb`

## Configuration File

Ensure that a nemesis.yaml file with the following values is in `~/.msf4/nemesis.yaml` (Msf::Config.get_config_root):

```
nemesis_url: http://NEMESIS_HOST:8080/api/
nemesis_creds: nemesis:Qwerty12345
operator_name: OPERATOR-X
project_name: PROJECT-X
expiration_days: 100
```

# Usage

## Downloads

To use the download hook, type `load nemesis`. This will submit all downloaded files to Nemesis for analysis.

## Data Collection

Using the `post/windows/gather/nemesis` module will collect any relevant data for submission to Nemesis.

# TODO

* Pull SDDL information for the registry keys through Railgun (won't be fun)
