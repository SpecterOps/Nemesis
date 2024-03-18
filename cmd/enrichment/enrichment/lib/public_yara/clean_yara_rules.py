# File that runs on docker build that cleans the Yara rules from /signature-base/
#   and outputs a single "signature-base.yara" to this directory
import plyara
import yara
import glob
import sys
from plyara import utils as plyara_utils
import time
import os

rules_dir = f"{os.path.dirname(os.path.realpath(__file__))}"

yara_file_paths = glob.glob("/signature-base/yara/**/*.yar*", recursive=True)

yara_rule_definitions = []
parser = plyara.Plyara()
for yara_file_path in yara_file_paths:
    with open(yara_file_path, 'r') as fh:
        try:
            parsed_yara_rules = parser.parse_string(fh.read())
            for parsed_yara_rule in parsed_yara_rules:
                try:
                    # only save this rule if it compiles
                    yara.compile(source=plyara_utils.rebuild_yara_rule(parsed_yara_rule))
                    yara_rule_definitions += [parsed_yara_rule]
                except Exception as e:
                    # print(f"Yara compile error for rule in path '{yara_file_path}' : {e}")
                    pass
        except Exception as e:
            print(f"Error parsing yara file '{yara_file_path}' : {e}")
            pass
    parser.clear()

with open(f"{rules_dir}/signature-base.yara", 'w') as f:
    temp = [plyara_utils.rebuild_yara_rule(parsed_yara_rule) for parsed_yara_rule in yara_rule_definitions]
    f.write("\n".join(temp))
