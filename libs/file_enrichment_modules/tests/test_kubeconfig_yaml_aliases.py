"""The kubeconfig parser must refuse YAML aliases, which let a tiny file expand exponentially."""

import json
import time

import pytest
import yaml
from file_enrichment_modules.kubeconfig.analyzer import KubeconfigParser, load_kubeconfig_yaml

from tests.harness import FileEnrichedFactory, ModuleTestHarness

KUBECONFIG = """apiVersion: v1
kind: Config
current-context: dev
clusters:
- name: dev-cluster
  cluster:
    server: https://k8s.example:6443
    extensions:
    - name: client.authentication.k8s.io/exec
      extension:
        audience: example
contexts:
- name: dev
  context:
    cluster: dev-cluster
    user: alice
users:
- name: alice
  user:
    token: abc123
"""


def alias_bomb(levels: int) -> str:
    """Each level references the previous one 10 times: 10**levels leaves from a few hundred bytes."""
    lines = ['a0: &a0 ["x"]']
    for i in range(1, levels + 1):
        lines.append(f"a{i}: &a{i} [" + ", ".join([f"*a{i - 1}"] * 10) + "]")
    return (
        "\n".join(lines)
        + f"""
apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://k8s.example
    extensions: *a{levels}
contexts: []
users:
- name: u
  user:
    token: t
"""
    )


def register(harness, tmp_path, content, object_id="kube"):
    path = tmp_path / "config"
    path.write_text(content)
    harness.register_file(
        object_id=object_id,
        local_path=str(path),
        file_enriched=FileEnrichedFactory.create_plaintext_file(
            object_id=object_id, file_name="config", size=len(content)
        ),
    )
    return str(path)


# --- loader ---


def test_loader_parses_a_normal_kubeconfig():
    assert load_kubeconfig_yaml(KUBECONFIG)["users"][0]["user"]["token"] == "abc123"


def test_loader_allows_anchors_without_aliases():
    assert load_kubeconfig_yaml("a: &anchor 1\nb: 2\n") == {"a": 1, "b": 2}


@pytest.mark.parametrize(
    "content",
    [
        alias_bomb(9),
        "base: &b {server: x}\ncluster: *b\n",
        "base: &b {server: x}\ncluster:\n  <<: *b\n",  # merge keys are aliases too
    ],
)
def test_loader_rejects_aliases(content):
    with pytest.raises(yaml.YAMLError, match="aliases are not allowed"):
        load_kubeconfig_yaml(content)


def test_loader_is_still_safe():
    with pytest.raises(yaml.constructor.ConstructorError):
        load_kubeconfig_yaml("!!python/object/apply:os.system ['true']")


# --- module ---


@pytest.mark.asyncio
async def test_kubeconfig_is_parsed(tmp_path):
    harness = ModuleTestHarness()
    path = register(harness, tmp_path, KUBECONFIG)
    async with harness.create_module(KubeconfigParser) as module:
        assert await module.should_process("kube", path) is True
        result = await module.process("kube", path)
    assert result.results["clusters"][0]["server"] == "https://k8s.example:6443"
    assert result.results["clusters"][0]["extensions"][0]["extension"] == {"audience": "example"}
    assert result.results["has_credentials"] is True


@pytest.mark.asyncio
async def test_alias_bomb_is_refused_quickly(tmp_path):
    # 9 levels is under 1 KB but would serialize to about 7 GB of JSON
    content = alias_bomb(9)
    assert len(content) < 1024
    harness = ModuleTestHarness()
    path = register(harness, tmp_path, content)
    async with harness.create_module(KubeconfigParser) as module:
        assert await module.should_process("kube", path) is True  # still detected as a kubeconfig
        start = time.monotonic()
        result = await module.process("kube", path)
    assert result is None
    assert time.monotonic() - start < 2


@pytest.mark.asyncio
async def test_results_stay_proportional_to_the_file(tmp_path):
    harness = ModuleTestHarness()
    path = register(harness, tmp_path, KUBECONFIG)
    async with harness.create_module(KubeconfigParser) as module:
        result = await module.process("kube", path)
    assert len(json.dumps(result.results)) < 10 * len(KUBECONFIG)
