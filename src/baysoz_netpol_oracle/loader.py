"""Strict multi-document manifest loader with duplicate-key rejection.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

import yaml
from yaml.nodes import MappingNode

from .model import (
    LabelSelector,
    ManifestError,
    Namespace,
    NetworkPolicy,
    PolicyRule,
    SUPPORTED_POLICY_TYPES,
    Topology,
    Workload,
)

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


class StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise yaml.constructor.ConstructorError(None, None, "expected a mapping node", node.start_mark)
        seen: set[str] = set()
        for key_node, _ in node.value:
            key = key_node.value
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate YAML key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{where}: expected a mapping")
    return value


def _string_labels(value: Any, where: str) -> dict[str, str]:
    if value is None:
        return {}
    labels = _mapping(value, where)
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in labels.items()):
        raise ManifestError(f"{where}: label keys and values must be strings")
    return dict(labels)


def _metadata(data: dict[str, Any], where: str) -> tuple[str, str, dict[str, str]]:
    meta = _mapping(data.get("metadata"), f"{where}.metadata")
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        raise ManifestError(f"{where}.metadata.name must be a non-empty string")
    namespace = meta.get("namespace", "default")
    if not isinstance(namespace, str) or not namespace:
        raise ManifestError(f"{where}.metadata.namespace must be a non-empty string")
    return name, namespace, _string_labels(meta.get("labels"), f"{where}.metadata.labels")


def _parse_namespace(data: dict[str, Any], source: str, line: int) -> Namespace:
    name, _, labels = _metadata(data, "Namespace")
    return Namespace(name=name, labels=labels, source=source, line=line)


def _parse_workload(data: dict[str, Any], source: str, line: int) -> Workload:
    name, namespace, labels = _metadata(data, "Pod")
    spec = _mapping(data.get("spec") or {}, "Pod.spec")
    containers = spec.get("containers") or []
    if not isinstance(containers, list):
        raise ManifestError("Pod.spec.containers must be a list")
    ports: list[tuple[str, str, int]] = []
    for c_index, container in enumerate(containers):
        container_map = _mapping(container, f"Pod.spec.containers[{c_index}]")
        declared = container_map.get("ports") or []
        if not isinstance(declared, list):
            raise ManifestError(f"Pod.spec.containers[{c_index}].ports must be a list")
        for p_index, raw_port in enumerate(declared):
            port_map = _mapping(raw_port, f"Pod.spec.containers[{c_index}].ports[{p_index}]")
            port_name = port_map.get("name")
            number = port_map.get("containerPort")
            protocol = str(port_map.get("protocol", "TCP")).upper()
            if port_name is None:
                continue
            if not isinstance(port_name, str) or not port_name:
                raise ManifestError(f"container port name at index {p_index} must be a non-empty string")
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535:
                raise ManifestError(f"container port {port_name!r} has invalid containerPort")
            ports.append((port_name, protocol, number))
    return Workload(
        name=name,
        namespace=namespace,
        labels=labels,
        ports=tuple(sorted(set(ports))),
        source=source,
        line=line,
    )


def _parse_policy_rules(spec: dict[str, Any], key: str, peer_key: str, where: str) -> tuple[PolicyRule, ...] | None:
    if key not in spec or spec[key] is None:
        return None
    raw_rules = spec[key]
    if not isinstance(raw_rules, list):
        raise ManifestError(f"{where}.spec.{key} must be a list")
    return tuple(
        PolicyRule.from_value(rule, f"{where}.spec.{key}[{index}]", peer_key)
        for index, rule in enumerate(raw_rules)
    )


def _parse_policy(data: dict[str, Any], source: str, line: int) -> NetworkPolicy:
    name, namespace, _ = _metadata(data, "NetworkPolicy")
    where = f"NetworkPolicy {namespace}/{name}"
    spec = _mapping(data.get("spec"), f"{where}.spec")
    if "podSelector" not in spec:
        raise ManifestError(f"{where}.spec.podSelector is required")
    pod_selector = LabelSelector.from_value(spec["podSelector"], f"{where}.spec.podSelector")
    ingress = _parse_policy_rules(spec, "ingress", "from", where)
    egress = _parse_policy_rules(spec, "egress", "to", where)
    raw_types = spec.get("policyTypes")
    explicit = raw_types is not None
    if explicit:
        if not isinstance(raw_types, list) or not all(isinstance(item, str) for item in raw_types):
            raise ManifestError(f"{where}.spec.policyTypes must be a list of strings")
        policy_types = frozenset(item.title() for item in raw_types)
        unknown = sorted(policy_types - SUPPORTED_POLICY_TYPES)
        if unknown:
            raise ManifestError(f"{where}.spec.policyTypes contains unsupported values {unknown}")
        if not policy_types:
            raise ManifestError(f"{where}.spec.policyTypes must not be empty")
    else:
        inferred = set()
        if ingress is not None:
            inferred.add("Ingress")
        if egress is not None:
            inferred.add("Egress")
        policy_types = frozenset(inferred or {"Ingress"})
    return NetworkPolicy(
        name=name,
        namespace=namespace,
        pod_selector=pod_selector,
        ingress=ingress,
        egress=egress,
        policy_types=policy_types,
        explicit_policy_types=explicit,
        source=source,
        line=line,
    )


def _expand_paths(paths: Sequence[str | Path]) -> tuple[tuple[str, int], ...]:
    expanded: list[tuple[str, int]] = []
    seen: set[str] = set()
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            raise ManifestError(f"path does not exist: {path}")
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        for file in files:
            if file.is_dir() or (path.is_dir() and file.suffix.lower() not in {".yaml", ".yml"}):
                continue
            key = str(file.resolve())
            if key not in seen:
                seen.add(key)
                expanded.append((str(file), 0))
    if not expanded:
        raise ManifestError("no YAML manifests found in the supplied paths")
    return tuple(expanded)


def load_topology(paths: Sequence[str | Path]) -> Topology:
    namespaces: dict[str, Namespace] = {}
    workloads: dict[tuple[str, str], Workload] = {}
    policies: dict[tuple[str, str], NetworkPolicy] = {}
    ignored: list[str] = []
    sources: list[str] = []

    def consume(data: Any, source: str, line: int) -> None:
        if data is None:
            return
        document = _mapping(data, f"{source}:{line}")
        kind = document.get("kind")
        if kind == "List":
            items = document.get("items") or []
            if not isinstance(items, list):
                raise ManifestError(f"{source}:{line}: List.items must be a list")
            for item in items:
                consume(item, source, line)
            return
        if kind == "Namespace":
            parsed_ns = _parse_namespace(document, source, line)
            if parsed_ns.name in namespaces:
                raise ManifestError(f"duplicate Namespace {parsed_ns.name} at {source}:{line}")
            namespaces[parsed_ns.name] = parsed_ns
        elif kind == "Pod":
            workload = _parse_workload(document, source, line)
            key = (workload.namespace, workload.name)
            if key in workloads:
                raise ManifestError(f"duplicate Pod {workload.id} at {source}:{line}")
            workloads[key] = workload
        elif kind == "NetworkPolicy":
            policy = _parse_policy(document, source, line)
            key = (policy.namespace, policy.name)
            if key in policies:
                raise ManifestError(f"duplicate NetworkPolicy {policy.id} at {source}:{line}")
            policies[key] = policy
        else:
            ignored.append(str(kind) if kind is not None else "<missing kind>")

    for source, _ in _expand_paths(paths):
        sources.append(source)
        text = Path(source).read_text(encoding="utf-8")
        loader = StrictSafeLoader(text)
        try:
            while loader.check_data():
                node = loader.get_node()
                data = loader.construct_document(node)
                consume(data, source, node.start_mark.line + 1)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            location = f" at line {mark.line + 1}" if mark is not None else ""
            raise ManifestError(f"invalid YAML in {source}{location}: {exc}") from exc
        except ManifestError as exc:
            raise ManifestError(f"{source}: {exc}") from exc

    for workload in workloads.values():
        namespaces.setdefault(workload.namespace, Namespace(name=workload.namespace))
    for policy in policies.values():
        namespaces.setdefault(policy.namespace, Namespace(name=policy.namespace))
    return Topology(
        namespaces=namespaces,
        workloads=workloads,
        policies=policies,
        sources=tuple(sources),
        ignored_kinds=tuple(sorted(set(ignored))),
    )


__all__ = ["ATTRIBUTION", "StrictSafeLoader", "load_topology"]
