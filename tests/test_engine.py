"""Bidirectional NetworkPolicy semantics tests.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import pytest

from baysoz_netpol_oracle.engine import Endpoint, query
from baysoz_netpol_oracle.loader import load_topology
from baysoz_netpol_oracle.model import ManifestError

PODS = """
apiVersion: v1
kind: Namespace
metadata:
  name: team-a
  labels:
    team: a
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-b
  labels:
    team: b
---
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: team-a
  labels:
    app: app
---
apiVersion: v1
kind: Pod
metadata:
  name: db
  namespace: team-b
  labels:
    app: db
spec:
  containers:
    - name: postgres
      ports:
        - name: postgres
          containerPort: 5432
"""


def topology(write_manifest, extra: str = ""):
    return load_topology([write_manifest("engine.yaml", PODS + "\n---\n" + extra)])


def test_no_policies_means_unrestricted(write_manifest):
    engine = topology(write_manifest)
    decision = query(engine, Endpoint.workload("team-a", "app"), Endpoint.workload("team-b", "db"), 443)
    assert decision.allowed
    assert not decision.ingress.isolated and not decision.egress.isolated
    assert "no ingress NetworkPolicy" in decision.ingress.evidence[0]
    assert "no egress NetworkPolicy" in decision.egress.evidence[0]


def test_default_deny_both_directions(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: team-b
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""
    engine = topology(write_manifest, extra)
    source = Endpoint.workload("team-a", "app")
    decision = query(engine, source, Endpoint.workload("team-b", "db"), 443)
    assert not decision.allowed
    assert "no ingress rule matched" in decision.ingress.evidence[0]
    assert decision.ingress.policies == ("team-b/deny-all",)


def test_policy_union_across_rules(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ports
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app: app
      ports:
        - port: 443
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app: app
      ports:
        - port: 80
"""
    engine = topology(write_manifest, extra)
    source = Endpoint.workload("team-a", "app")
    destination = Endpoint.workload("team-b", "db")
    for port in (80, 443):
        decision = query(engine, source, destination, port)
        assert decision.allowed
        assert "team-b/allow-ports ingress rule" in decision.ingress.evidence[0]
    assert not query(engine, source, destination, 8080).allowed


def test_omitted_and_empty_from_match_any_peer(write_manifest):
    manifests = (
        """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: open-omitted
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - ports:
        - port: 443
""",
        """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: open-empty
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - from:
        - {}
      ports:
        - port: 443
""",
    )
    for extra in manifests:
        engine = topology(write_manifest, extra)
        decision = query(engine, Endpoint.ip("203.0.113.7"), Endpoint.workload("team-b", "db"), 443)
        assert decision.allowed
        assert "any source" in decision.ingress.evidence[0]


def test_namespace_and_pod_selectors_are_conjoined(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cross-namespace
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              team: a
          podSelector:
            matchLabels:
              app: app
"""
    engine = topology(write_manifest, extra)
    source = Endpoint.workload("team-a", "app")
    destination = Endpoint.workload("team-b", "db")
    assert query(engine, source, destination, 443).allowed
    wrong_team = topology(write_manifest, extra.replace("team: a", "team: c"))
    assert not query(wrong_team, source, destination, 443).allowed


def test_pod_selector_alone_is_same_namespace_only(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: same-namespace
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: app
"""
    engine = topology(write_manifest, extra)
    source = Endpoint.workload("team-a", "app")
    decision = query(engine, source, Endpoint.workload("team-b", "db"), 443)
    assert not decision.allowed


def test_ipblock_except_boundary(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cidr-gate
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8
            except:
              - 10.1.0.0/16
"""
    engine = topology(write_manifest, extra)
    destination = Endpoint.workload("team-b", "db")
    assert query(engine, Endpoint.ip("10.0.1.5"), destination, 443).allowed
    assert not query(engine, Endpoint.ip("10.1.2.3"), destination, 443).allowed
    assert not query(engine, Endpoint.workload("team-a", "app"), destination, 443).allowed


def test_named_port_binds_to_destination(write_manifest):
    extra = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-port
  namespace: team-b
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
    - from:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: postgres
"""
    engine = topology(write_manifest, extra)
    destination = Endpoint.workload("team-b", "db")
    source = Endpoint.workload("team-a", "app")
    assert query(engine, source, destination, 5432).allowed
    assert not query(engine, source, destination, 5433).allowed
    udp_engine = topology(write_manifest, extra.replace("protocol: TCP", "protocol: UDP"))
    assert not query(udp_engine, source, destination, 5432, "UDP").allowed


def test_policy_types_inference(write_manifest):
    egress_only = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-only
  namespace: team-a
spec:
  podSelector:
    matchLabels:
      app: app
  egress:
    - {}
"""
    engine = topology(write_manifest, egress_only)
    outbound = query(engine, Endpoint.workload("team-a", "app"), Endpoint.ip("8.8.8.8"), 443)
    assert outbound.egress.isolated
    assert outbound.egress.allowed
    assert query(engine, Endpoint.ip("8.8.8.8"), Endpoint.workload("team-a", "app"), 443).ingress.allowed
    empty = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: empty
  namespace: team-a
spec:
  podSelector: {}
"""
    empty_engine = topology(write_manifest, empty)
    decision = query(empty_engine, Endpoint.ip("8.8.8.8"), Endpoint.workload("team-a", "app"), 443)
    assert not decision.allowed
    assert decision.ingress.isolated and not decision.egress.isolated


def test_unknown_endpoint_is_hard_error(write_manifest):
    engine = topology(write_manifest)
    with pytest.raises(ManifestError, match="unknown source workload"):
        query(engine, Endpoint.workload("team-a", "missing"), Endpoint.ip("8.8.8.8"), 443)
    with pytest.raises(ManifestError, match="invalid IP address"):
        Endpoint.ip("not-an-ip")
