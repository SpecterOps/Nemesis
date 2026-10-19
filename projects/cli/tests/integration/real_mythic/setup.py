"""Build an isolated copy of Mythic without loading any .env files."""

import argparse
import shutil
import subprocess
from pathlib import Path

import httpx
import yaml
from graphql import parse, print_ast


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--workdir", type=Path, default=Path("/tmp/nemesis-real-mythic"))
    parser.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    workdir = args.workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    if not args.metadata_only:
        shutil.copytree(
            args.source / "mythic-docker",
            workdir / "server",
            ignore=shutil.ignore_patterns(".env*", ".git"),
            dirs_exist_ok=True,
        )
        config = workdir / "server/src/utils/config.go"
        text = config.read_text()
        start = text.index("\t// pull in environment variables")
        end = text.index("\tsetConfigFromEnv(mythicEnv)", start)
        config.write_text(text[:start] + "\tmythicEnv.AutomaticEnv()\n" + text[end:])
        for name in ("compose.yaml", "nginx.conf"):
            shutil.copyfile(Path(__file__).parent / name, workdir / name)
        subprocess.run(["docker", "build", "-t", "nemesis-real-mythic:test", str(workdir / "server")], check=True)
        subprocess.run(
            ["docker", "compose", "--env-file", "/dev/null", "-f", str(workdir / "compose.yaml"), "up", "-d"],
            check=True,
        )
        print("Wait for Mythic initialization, then rerun with --metadata-only.")
        return
    metadata_dir = args.source / "hasura-docker/metadata"
    metadata = {"version": 2}
    for name in ("tables", "functions", "actions", "cron_triggers", "query_collections", "allow_list"):
        path = metadata_dir / f"{name}.yaml"
        if path.is_file():
            value = yaml.safe_load(path.read_text())
            if isinstance(value, dict):
                metadata.update(value)
            else:
                metadata[name] = value
    # The Hasura CLI combines actions.yaml with actions.graphql on import.
    # Reproduce that conversion without running its configuration loader.
    document = parse((metadata_dir / "actions.graphql").read_text())
    actions = {action["name"]: action for action in metadata.get("actions", [])}
    categories = {
        "object_type_definition": "objects",
        "input_object_type_definition": "input_objects",
        "scalar_type_definition": "scalars",
        "enum_type_definition": "enums",
    }
    custom = metadata.setdefault("custom_types", {})
    for definition in document.definitions:
        name = definition.name.value
        if name in ("Query", "Mutation"):
            for field in definition.fields:
                action = actions[field.name.value]["definition"]
                action.update(
                    type=name.lower(),
                    output_type=print_ast(field.type),
                    arguments=[{"name": arg.name.value, "type": print_ast(arg.type)} for arg in field.arguments],
                )
            continue
        category = categories[definition.kind]
        items = custom.setdefault(category, [])
        item = next((item for item in items if item["name"] == name), None)
        if item is None:
            item = {"name": name}
            items.append(item)
        if category in ("objects", "input_objects"):
            item["fields"] = [{"name": field.name.value, "type": print_ast(field.type)} for field in definition.fields]
        elif category == "enums":
            item["values"] = [{"value": value.name.value} for value in definition.values]
    response = httpx.post(
        "http://127.0.0.1:18081/v1/metadata",
        headers={"x-hasura-admin-secret": "isolated-test-admin"},
        json={"type": "replace_metadata", "args": metadata},
        timeout=60,
    )
    print(response.text)
    response.raise_for_status()


if __name__ == "__main__":
    main()
