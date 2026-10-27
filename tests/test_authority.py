import pytest

from mlacp_core.authority import CapabilityChain
from mlacp_core.errors import DelegationEscalation, NotPermitted


def chain():
    c = CapabilityChain()
    root = c.issue_root("mlacp:stavka/center/main/command",
                        ["send", "delegate", "revoke"])
    return c, root


def test_delegation_shrinks():
    c, root = chain()
    gid = c.delegate(root, "mlacp:front/west/hq/command", ["send"])
    assert c.authorize("mlacp:front/west/hq/command", "send").grant_id == gid


def test_escalation_refused_by_name():
    c, root = chain()
    with pytest.raises(DelegationEscalation) as e:
        c.delegate(root, "mlacp:front/west/hq/command", ["send", "nuclear"])
    assert "nuclear" in str(e.value)


def test_authorize_without_grant_refused():
    c, root = chain()
    with pytest.raises(NotPermitted):
        c.authorize("mlacp:front/east/hq/command", "send")


def test_revocation_cascades():
    c, root = chain()
    mid = c.delegate(root, "mlacp:front/west/hq/command", ["send"])
    leaf = c.delegate(mid, "mlacp:front/west/ct-1/dispatch", ["send"])
    assert c.authorize("mlacp:front/west/ct-1/dispatch", "send")
    n = c.revoke(root)
    assert n == 3  # root + mid + leaf
    with pytest.raises(NotPermitted):
        c.authorize("mlacp:front/west/ct-1/dispatch", "send")
    with pytest.raises(NotPermitted):
        c.delegate(mid, "mlacp:front/west/ct-2/dispatch", ["send"])


def test_history_records_custody():
    c, root = chain()
    mid = c.delegate(root, "mlacp:front/west/hq/command", ["send"])
    c.revoke(mid)
    h = c.history()
    assert any("delegate" in x for x in h)
    assert any("revoke" in x for x in h)
