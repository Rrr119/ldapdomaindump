import json
import os
import re

import pytest

from ldapdomaindump import domainDumpConfig, domainDumper
from ldapdomaindump.incremental import (
    IncrementalCollector, _encode_value, _new_entry
)


BASE_DN = 'DC=example,DC=com'
PAGED_RESULTS_OID = '1.2.840.113556.1.4.319'


def make_entry(record):
    dn = record['distinguishedName'][0]
    attributes = dict(
        (name, [_encode_value(value) for value in values])
        for name, values in record.items()
    )
    return _new_entry(dn, attributes, attributes)


def user_record(index, usn=None):
    guid = index.to_bytes(16, 'big')
    return {
        'uSNChanged': [usn if usn is not None else index + 1],
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'objectCategory': ['CN=Person,CN=Schema,CN=Configuration,DC=example,DC=com'],
        'objectGUID': [guid],
        'distinguishedName': ['CN=user%d,OU=Users,%s' % (index, BASE_DN)],
        'cn': ['user%d' % index],
        'sAMAccountName': ['user%d' % index],
        'primaryGroupId': [513],
        'description': ['unchanged'],
    }


class FakeConnection:
    def __init__(self, records, page_size=None, crash_at_call=None):
        self.records = records
        self.page_size = page_size
        self.crash_at_call = crash_at_call
        self.calls = 0
        self.result = {}
        self.entries = []

    def search(self, base, search_filter, attributes=None, paged_size=None,
               paged_cookie=None, controls=None, **kwargs):
        self.calls += 1
        if self.crash_at_call == self.calls:
            raise RuntimeError('simulated connection failure')

        match = re.search(r'uSNChanged([><])=?(\d+)', search_filter)
        start_usn = int(match.group(2))
        inclusive = match.group(1) == '>'
        deleted = '(isDeleted=TRUE)' in search_filter
        matching = []
        for record in self.records:
            record_deleted = str(
                record.get('isDeleted', ['FALSE'])[0]
            ).upper() == 'TRUE'
            usn = int(record['uSNChanged'][0])
            if record_deleted != deleted:
                continue
            if usn < start_usn or (usn == start_usn and not inclusive):
                continue
            matching.append(record)

        offset = int(paged_cookie or b'0')
        size = paged_size or self.page_size or 500
        page = matching[offset:offset + size]
        next_offset = offset + len(page)
        cookie = (
            str(next_offset).encode('ascii')
            if next_offset < len(matching) else b''
        )
        self.entries = [make_entry(record) for record in page]
        self.result = {
            'result': 0,
            'description': 'success',
            'controls': {
                PAGED_RESULTS_OID: {'value': {'cookie': cookie}}
            },
        }
        return True


class FakeInfo:
    def __init__(self, invocation_id):
        self.other = {'invocationID': [invocation_id]}


class FakeServer:
    def __init__(self, host, invocation_id):
        self.host = host
        self.info = FakeInfo(invocation_id)


def read_state(path):
    with open(path, 'r', encoding='utf-8') as state_file:
        return json.load(state_file)


def test_100k_objects_incremental_only_returns_changes(tmp_path):
    records = [user_record(index) for index in range(100000)]
    state_path = str(tmp_path / 'state.json')

    baseline_connection = FakeConnection(records)
    baseline = IncrementalCollector(
        baseline_connection,
        BASE_DN,
        state_path,
        page_size=1000,
        minimal=True,
    ).run()

    assert baseline.baseline is True
    assert baseline.inventory_count == 100000
    assert len(baseline.entries_by_type['users']) == 100000
    assert baseline.to_usn == 100000
    assert read_state(state_path)['last_usn'] == 100000
    assert baseline_connection.calls == 100

    modified = [1, 250, 5000, 75000, 99999]
    modified_dns = [
        records[index]['distinguishedName'][0] for index in modified
    ]
    next_usn = 100001
    for index in modified:
        records[index]['description'] = ['changed']
        records[index]['uSNChanged'] = [next_usn]
        next_usn += 1

    added = []
    for index in range(100000, 100003):
        record = user_record(index, usn=next_usn)
        added.append(record)
        records.append(record)
        next_usn += 1

    deleted_indexes = [2, 60000]
    deleted_dns = [
        records[index]['distinguishedName'][0] for index in deleted_indexes
    ]
    tombstones = []
    for index in deleted_indexes:
        tombstone = dict(records[index])
        tombstone['uSNChanged'] = [next_usn]
        tombstone['distinguishedName'] = [
            'CN=deleted%d,CN=Deleted Objects,%s' % (index, BASE_DN)
        ]
        tombstone['isDeleted'] = ['TRUE']
        tombstones.append(tombstone)
        next_usn += 1
    deleted_guids = set(
        records[index]['objectGUID'][0] for index in deleted_indexes
    )
    records = [
        record for record in records
        if record['objectGUID'][0] not in deleted_guids
    ]
    records.extend(tombstones)

    incremental_connection = FakeConnection(records)
    incremental = IncrementalCollector(
        incremental_connection,
        BASE_DN,
        state_path,
        page_size=1000,
        minimal=True,
    ).run()

    assert incremental.baseline is False
    assert incremental.summary() == {'add': 3, 'modify': 5, 'delete': 2}
    assert len(incremental.changes) == 10
    actual_changes = set(
        (change.operation, change.dn) for change in incremental.changes
    )
    expected_changes = set(
        ('modify', dn) for dn in modified_dns
    )
    expected_changes.update(
        ('add', record['distinguishedName'][0]) for record in added
    )
    expected_changes.update(('delete', dn) for dn in deleted_dns)
    assert actual_changes == expected_changes
    assert incremental_connection.calls == 2


def test_paged_checkpoint_resumes_without_duplicates(tmp_path):
    records = [user_record(index) for index in range(7)]
    state_path = str(tmp_path / 'state.json')

    with pytest.raises(RuntimeError, match='simulated connection failure'):
        IncrementalCollector(
            FakeConnection(records, crash_at_call=3),
            BASE_DN,
            state_path,
            page_size=2,
            minimal=True,
        ).run()

    pending_state = read_state(state_path)
    assert pending_state['pending']['objects_complete'] is False
    assert pending_state['pending']['object_usn'] == 4
    assert pending_state['pending']['cookie'] is not None

    resumed_connection = FakeConnection(records)
    resumed = IncrementalCollector(
        resumed_connection,
        BASE_DN,
        state_path,
        page_size=2,
        minimal=True,
    ).run()

    assert resumed.baseline is True
    assert resumed.inventory_count == 7
    assert sorted(entry.cn.value for entry in resumed.entries_by_type['users']) == [
        'user%d' % index for index in range(7)
    ]
    assert read_state(state_path)['pending'] is None
    assert not os.path.exists(state_path + '.stage')


def test_second_run_writes_diff_with_only_changed_objects(tmp_path):
    records = [user_record(index) for index in range(5)]
    config = domainDumpConfig()
    config.basepath = str(tmp_path)
    config.incremental = True
    config.minimal = True

    first_connection = FakeConnection(records)
    first_dump = domainDumper(
        None, first_connection, config, root=BASE_DN
    )
    first_dump.domainDump()

    records[1]['description'] = ['modified']
    records[1]['uSNChanged'] = [6]
    records.append(user_record(99, usn=7))
    second_dump = domainDumper(
        None, FakeConnection(records), config, root=BASE_DN
    )
    second_dump.domainDump()

    with open(tmp_path / 'domain_diff.json', 'r', encoding='utf-8') as diff_file:
        diff = json.load(diff_file)

    assert diff['summary'] == {'add': 1, 'modify': 1, 'delete': 0}
    assert len(diff['changes']) == 2
    assert set(change['operation'] for change in diff['changes']) == {
        'add', 'modify'
    }
    assert all(
        change['dn'] in (
            'CN=user1,OU=Users,%s' % BASE_DN,
            'CN=user99,OU=Users,%s' % BASE_DN,
        )
        for change in diff['changes']
    )

    # The previous full baseline must not be replaced by a partial dump.
    with open(tmp_path / 'domain_users.json', 'r', encoding='utf-8') as users_file:
        baseline_users = json.load(users_file)
    assert len(baseline_users) == 5

    third_dump = domainDumper(
        None, FakeConnection(records), config, root=BASE_DN
    )
    third_dump.domainDump()
    with open(tmp_path / 'domain_diff.json', 'r', encoding='utf-8') as diff_file:
        empty_diff = json.load(diff_file)
    assert empty_diff['summary'] == {'add': 0, 'modify': 0, 'delete': 0}
    assert empty_diff['changes'] == []


def test_changed_dc_invocation_id_starts_new_baseline(tmp_path):
    records = [user_record(index) for index in range(3)]
    state_path = str(tmp_path / 'state.json')

    first_connection = FakeConnection(records)
    first_connection.server = FakeServer('dc1', b'first-dc')
    IncrementalCollector(
        first_connection, BASE_DN, state_path, page_size=2, minimal=True
    ).run()

    records[0]['description'] = ['modified']
    records[0]['uSNChanged'] = [4]
    second_connection = FakeConnection(records)
    second_connection.server = FakeServer('dc2', b'second-dc')
    result = IncrementalCollector(
        second_connection, BASE_DN, state_path, page_size=2, minimal=True
    ).run()

    assert result.baseline is True
    assert result.inventory_count == 3
    assert result.summary() == {'add': 0, 'modify': 0, 'delete': 0}
