#!/usr/bin/env python3
import argparse
import glob
import os

import plyara
import yara_x
from plyara import utils as plyara_utils


def clean_yara_rules(input_dir: str, output_file: str | None = None) -> None:
    """
    Clean and combine Yara rules from input directory into a single file.

    Args:
        input_dir (str): Directory containing Yara rules to process
        output_file (str, optional): Path to the output file.
                                   If not specified, uses 'signature-base.yara' in the script's directory.
    """
    if output_file is None:
        output_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "signature-base.yara")

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Create full path pattern for searching Yara files
    yara_pattern = os.path.join(input_dir, "**", "*.yar*")
    yara_file_paths = glob.glob(yara_pattern, recursive=True)

    if not yara_file_paths:
        print(f"No Yara files found in {input_dir}")
        return

    yara_rule_definitions = []
    parser = plyara.Plyara()

    for yara_file_path in yara_file_paths:
        with open(yara_file_path) as fh:
            try:
                parsed_yara_rules = parser.parse_string(fh.read())
                for parsed_yara_rule in parsed_yara_rules:
                    try:
                        # Only save this rule if it compiles
                        yara_x.compile(plyara_utils.rebuild_yara_rule(parsed_yara_rule))
                        yara_rule_definitions.append(parsed_yara_rule)
                    except Exception as e:
                        print(f"Yara compile error in '{yara_file_path}': {e}")
            except Exception as e:
                print(f"Error parsing yara file '{yara_file_path}': {e}")
        parser.clear()

    with open(output_file, "w") as f:
        rules_text = [plyara_utils.rebuild_yara_rule(rule) for rule in yara_rule_definitions]
        f.write("\n".join(rules_text))

    print(f"Successfully processed {len(yara_rule_definitions)} rules")
    print(f"Output written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Clean and combine all Yara rules from a directory (and its recursive subdirectories) into a single file"
    )
    parser.add_argument(
        "-i",
        "--input-dir",
        help="Input directory containing Yara rules",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        help="Output file path for the combined rules",
    )

    args = parser.parse_args()

    # Verify input directory exists
    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' does not exist")
        return 1

    try:
        clean_yara_rules(args.input_dir, args.output_file)
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
