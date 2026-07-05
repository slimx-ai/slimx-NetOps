"""Security-critical: the read-only allowlist must accept diagnostics and refuse everything else."""

from __future__ import annotations

import pytest

from slimx_netops.allowlist import (
    AllowlistError,
    validate_oid,
    validate_oids,
    validate_show_command,
)


@pytest.mark.parametrize(
    "command",
    [
        "show crypto ipsec sa peer 203.0.113.10",
        "show ip bgp summary",
        "show ip bgp neighbors 10.20.0.1",
        "show running-config | section crypto ipsec",
        "display current-configuration",
        "show logging | include IKE",
        "show interfaces | include errors",
    ],
)
def test_valid_show_commands_pass(command):
    assert validate_show_command(command) == " ".join(command.split())


@pytest.mark.parametrize(
    "command",
    [
        "configure terminal",
        "conf t",
        "write memory",
        "copy running-config startup-config",
        "reload",
        "reboot",
        "clear ip bgp *",
        "no router bgp 65010",
        "delete flash:file",
        "erase startup-config",
        "request system reboot",
        "debug ip packet",
        "tclsh",
        "guestshell run bash",
        "ping 8.8.8.8",  # active, not a show
        "traceroute 8.8.8.8",
        "",
        "show",  # bare verb, no subject
    ],
)
def test_mutating_or_non_show_commands_refused(command):
    with pytest.raises(AllowlistError):
        validate_show_command(command)


@pytest.mark.parametrize(
    "command",
    [
        "show run ; reload",
        "show run && configure terminal",
        "show run | tee flash:out.txt",
        "show run | redirect flash:out.txt",
        "show version `reboot`",
        "show version $(reload)",
        "show run\nconfigure terminal",
        "show run > flash:out.txt",
    ],
)
def test_injection_and_redirection_refused(command):
    with pytest.raises(AllowlistError):
        validate_show_command(command)


def test_pipe_filter_must_be_read_only():
    assert validate_show_command("show run | include lifetime")
    with pytest.raises(AllowlistError):
        validate_show_command("show run | save flash:x")


@pytest.mark.parametrize("oid", ["1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.2.2.1.14.7", "1.3.6.1.2.1"])
def test_valid_oids_pass(oid):
    assert validate_oid(oid).startswith("1.3.6.1.2.1")


@pytest.mark.parametrize(
    "oid",
    [
        "1.3.6.1.4.1.9.9.999.1",  # enterprise branch, not allowlisted
        "1.3.6.1.3.1",  # experimental
        "not.an.oid",
        "",
        "1.3.6.1.2.1; reboot",
    ],
)
def test_disallowed_oids_refused(oid):
    with pytest.raises(AllowlistError):
        validate_oid(oid)


def test_too_many_oids_refused():
    with pytest.raises(AllowlistError):
        validate_oids(["1.3.6.1.2.1.1.3.0"] * 65)
