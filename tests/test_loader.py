"""Tests for strict manifest loading and the immutable model.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import pytest

from baysoz_netpol_oracle.loader import load_topology
from baysoz_netpol_oracle.model import IPBlock, LabelSelector, ManifestError, MatchExpression, PortRule

BASIC = """
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
  labels:
    team: a
---
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: team-a
  labels:
    app: web
spec:
  containers:
    - name: web
      ports:
        - name: http
          containerPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-in
  namespace: team-a
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8
            except:
              - 10.1.0.0/16
      ports:
        - protocol: TCP
          port: 8080
"""


def test_load_basic_topology(write_manifest):
    topology = load_topology([write_manifest("basic.yaml", BASIC)])
    assert len(topology.namespaces) == 1
    assert len(topology.workloads) == 1
    assert len(topology.policies) == 1
    policy = topology.policies[("team-a", "web-in")]
    assert policy.policy_types == frozenset({"Ingress"})
    assert policy.explicit_policy_types is False
    assert policy.ingress is not None
    block = policy.ingress[0].peers[0].ip_block
    assert str(block.cidr) == "10.0.0.0/8"
    assert [str(item) for item in block.excepts] == ["10.1.0.0/16"]
    assert topology.workloads[("team-a", "web")].named_port("http", "TCP") == 8080


def test_duplicate_yaml_key_is_rejected(write_manifest):
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: web
  name: web2
"""
    with pytest.raises(ManifestError, match="duplicate YAML key"):
        load_topology([write_manifest("duplicate.yaml", manifest)])


def test_duplicate_resource_is_rejected(write_manifest):
    pod = """
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: default
"""
    with pytest.raises(ManifestError, match="duplicate Pod"):
        load_topology([write_manifest("dup.yaml", pod + "\n---\n" + pod)])


def test_list_kind_is_expanded(write_manifest):
    manifest = """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: one
      namespace: default
  - apiVersion: v1
    kind: Pod
    metadata:
      name: two
      namespace: default
"""
    topology = load_topology([write_manifest("list.yaml", manifest)])
    assert set(topology.workloads) == {("default", "one"), ("default", "two")}
    assert "default" in topology.namespaces


def test_unknown_kind_is_recorded(write_manifest):
    manifest = """
apiVersion: v1
kind: Service
metadata:
  name: svc
"""
    topology = load_topology([write_manifest("service.yaml", manifest)])
    assert topology.ignored_kinds == ("Service",)


def test_invalid_cidr_and_except_are_rejected():
    with pytest.raises(ManifestError, match="invalid ipBlock.cidr"):
        IPBlock.from_value({"cidr": "10.0.0.1/8"}, "test")
    with pytest.raises(ManifestError, match="not inside"):
        IPBlock.from_value({"cidr": "10.0.0.0/8", "except": ["192.168.0.0/16"]}, "test")


def test_selector_validation():
    selector = LabelSelector.from_value(
        {
            "matchLabels": {"app": "web"},
            "matchExpressions": [{"key": "tier", "operator": "In", "values": ["front", "edge"]}],
        },
        "test",
    )
    assert selector.matches({"app": "web", "tier": "edge"})
    assert not selector.matches({"app": "web", "tier": "db"})
    with pytest.raises(ManifestError, match="unsupported operator"):
        LabelSelector.from_value({"matchExpressions": [{"key": "x", "operator": "Like"}]}, "test")


def test_match_expression_operators():
    assert MatchExpression("tier", "NotIn", ("db",)).matches({"app": "web"})
    assert not MatchExpression("tier", "DoesNotExist").matches({"tier": "web"})
    assert MatchExpression("tier", "Exists").matches({"tier": "web"})


def test_port_rule_validation():
    with pytest.raises(ManifestError, match="unsupported protocol"):
        PortRule.from_value({"protocol": "ICMP", "port": 80}, "test")
    with pytest.raises(ManifestError, match="outside"):
        PortRule.from_value({"port": 70000}, "test")
    assert PortRule.from_value({}, "test").port is None
