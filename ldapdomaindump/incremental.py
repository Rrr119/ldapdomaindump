import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import ldap3
from ldap3 import ObjectDef
from ldap3.abstract.attribute import Attribute
from ldap3.abstract.entry import Entry


STATE_VERSION = 1
PAGED_RESULTS_OID = '1.2.840.113556.1.4.319'
SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
DEFAULT_PAGE_SIZE = 500

OBJECT_FILTER = (
    '(|(&(objectCategory=person)(objectClass=user))'
    '(&(objectClass=computer)(objectClass=user))'
    '(objectClass=group)(objectClass=domain)(objectClass=trustedDomain))'
)

POLICY_ATTRIBUTES = [
    'distinguishedName', 'lockOutObservationWindow', 'lockoutDuration',
    'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength',
    'pwdHistoryLength', 'pwdProperties', 'ms-DS-MachineAccountQuota'
]
TRUST_ATTRIBUTES = [
    'cn', 'flatName', 'securityIdentifier', 'trustAttributes',
    'trustDirection', 'trustType'
]

# These attributes are needed to build an inventory and to classify an object.
INCREMENTAL_ATTRIBUTES = [
    'uSNChanged', 'objectGUID', 'objectClass', 'objectCategory',
    'distinguishedName', 'isDeleted'
]

_TYPE_TAG = '__ldd_type__'


class IncrementalStateError(Exception):
    pass


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _encode_value(value):
    if isinstance(value, (bytes, bytearray)):
        return {
            _TYPE_TAG: 'bytes',
            'value': base64.b64encode(bytes(value)).decode('ascii')
        }
    if isinstance(value, datetime):
        return {_TYPE_TAG: 'datetime', 'value': value.isoformat()}
    if isinstance(value, timedelta):
        return {_TYPE_TAG: 'timedelta', 'value': [
            value.days, value.seconds, value.microseconds
        ]}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return {_TYPE_TAG: 'list', 'value': [_encode_value(item) for item in value]}
    return {_TYPE_TAG: 'str', 'value': str(value)}


def _decode_value(value):
    if not isinstance(value, dict) or _TYPE_TAG not in value:
        return value
    value_type = value[_TYPE_TAG]
    if value_type == 'bytes':
        return base64.b64decode(value['value'])
    if value_type == 'datetime':
        text = value['value']
        try:
            return datetime.strptime(text, '%Y-%m-%dT%H:%M:%S.%f')
        except ValueError:
            return datetime.strptime(text, '%Y-%m-%dT%H:%M:%S')
    if value_type == 'timedelta':
        days, seconds, microseconds = value['value']
        return timedelta(days=days, seconds=seconds, microseconds=microseconds)
    if value_type == 'list':
        return [_decode_value(item) for item in value['value']]
    if value_type == 'str':
        return value['value']
    return value


def _canonicalize(value):
    if isinstance(value, list):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(
            item, sort_keys=True, separators=(',', ':'), ensure_ascii=True
        ))
    if isinstance(value, dict):
        return dict((key, _canonicalize(item)) for key, item in value.items())
    return value


def _atomic_json_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.exists(directory):
        os.makedirs(directory)
    fd, temp_path = tempfile.mkstemp(prefix='.ldd-state-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(data, output, ensure_ascii=True, sort_keys=True, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _read_json(path):
    with open(path, 'r', encoding='utf-8') as state_file:
        return json.load(state_file)


def _utc_timestamp():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + 'Z'


def _record_digest(attributes):
    comparable = dict(
        (name.lower(), value)
        for name, value in attributes.items()
        if name.lower() not in ('usnchanged', 'isdeleted')
    )
    comparable = _canonicalize(comparable)
    encoded = json.dumps(
        comparable, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    )
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def _values_for(attributes, name):
    for attribute_name, values in attributes.items():
        if attribute_name.lower() == name.lower():
            return values
    return []


def _record_identity(attributes):
    guid = _values_for(attributes, 'objectGUID')
    if guid:
        encoded = json.dumps(
            _canonicalize(guid), sort_keys=True, separators=(',', ':'),
            ensure_ascii=True
        )
        return 'guid:' + hashlib.sha256(encoded.encode('utf-8')).hexdigest()
    dn = _values_for(attributes, 'distinguishedName')
    if dn:
        return 'dn:' + str(dn[0]).lower()
    return None


def _record_category(attributes):
    object_classes = set(
        str(value).lower() for value in _values_for(attributes, 'objectClass')
    )
    if 'trusteddomain' in object_classes:
        return 'trusts'
    if 'domain' in object_classes:
        return 'policy'
    if 'group' in object_classes:
        return 'groups'
    if 'computer' in object_classes:
        return 'computers'
    if 'user' in object_classes:
        return 'users'
    return None


def _record_usn(attributes):
    values = _values_for(attributes, 'uSNChanged')
    if not values:
        return 0
    try:
        return int(values[0])
    except (TypeError, ValueError):
        return 0


def entry_to_record(entry, deleted=False):
    attributes = {}
    raw_attributes = {}
    for name, attribute in entry._state.attributes.items():
        attributes[name] = [_encode_value(value) for value in _as_list(attribute.values)]
        raw_attributes[name] = [
            _encode_value(value) for value in _as_list(attribute.raw_values)
        ]

    identity = _record_identity(attributes)
    if identity is None:
        identity = 'dn:' + entry.entry_dn.lower()
    return {
        'key': identity,
        'dn': entry.entry_dn,
        'category': _record_category(attributes),
        'usn': _record_usn(attributes),
        'deleted': bool(deleted),
        'attributes': attributes,
        'raw_attributes': raw_attributes,
    }


def _new_entry(dn, attributes, raw_attributes):
    object_definition = ObjectDef()
    object_definition += list(attributes.keys())
    cursor = SimpleNamespace(
        definition=object_definition,
        connection=None,
        get_operational_attributes=False,
        controls=None,
    )
    entry = Entry(dn, cursor)
    for name, values in attributes.items():
        attribute = Attribute(object_definition._attributes[name], entry, cursor)
        attribute.values = [_decode_value(value) for value in values]
        raw_values = raw_attributes.get(name, values)
        attribute.raw_values = [_decode_value(value) for value in raw_values]
        entry._state.attributes[name] = attribute
        entry.__dict__[name] = attribute
    return entry


def record_to_entry(record):
    return _new_entry(
        record['dn'], record['attributes'], record.get('raw_attributes', {})
    )


def _cookie_as_text(cookie):
    if cookie is None or cookie == b'' or cookie == '':
        return None
    if isinstance(cookie, str):
        return cookie
    return 'b64:' + base64.b64encode(cookie).decode('ascii')


def _cookie_from_text(cookie):
    if not cookie:
        return None
    if cookie.startswith('b64:'):
        return base64.b64decode(cookie[4:])
    return cookie.encode('ascii')


def _response_cookie(result):
    controls = (result or {}).get('controls') or {}
    paged = controls.get(PAGED_RESULTS_OID) or {}
    value = paged.get('value') or {}
    return _cookie_as_text(value.get('cookie'))


def connection_identity(connection):
    server = getattr(connection, 'server', None)
    if server is None:
        return None
    info = getattr(server, 'info', None)
    if info is not None and getattr(info, 'other', None):
        invocation_id = info.other.get('invocationID')
        if not invocation_id:
            for key, value in info.other.items():
                if key.lower() == 'invocationid':
                    invocation_id = value
                    break
        if invocation_id:
            value = _as_list(invocation_id)[0]
            if isinstance(value, bytes):
                value = base64.b64encode(value).decode('ascii')
            return 'invocationID:' + str(value)
    host = getattr(server, 'host', None)
    if host:
        return 'host:' + str(host)
    return None


class StagingLog:
    def __init__(self, path):
        self.path = path

    def reset(self):
        directory = os.path.dirname(os.path.abspath(self.path))
        if not os.path.exists(directory):
            os.makedirs(directory)
        with open(self.path, 'w', encoding='utf-8'):
            pass

    def append(self, records):
        with open(self.path, 'a', encoding='utf-8') as output:
            for record in records:
                output.write(json.dumps(
                    record, ensure_ascii=True, sort_keys=True,
                    separators=(',', ':')
                ))
                output.write('\n')
            output.flush()
            os.fsync(output.fileno())

    def exists(self):
        return os.path.exists(self.path)

    def records(self):
        if not self.exists():
            return []
        records = []
        with open(self.path, 'r', encoding='utf-8') as staged:
            for line in staged:
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    # A crash can leave the last line incomplete. Everything
                    # before it was committed at a page boundary.
                    break
        return records

    def clear(self):
        if self.exists():
            os.unlink(self.path)


class DiffChange:
    def __init__(self, operation, category, dn, entry=None):
        self.operation = operation
        self.category = category
        self.dn = dn
        self.entry = entry

    def to_dict(self):
        change = {
            'operation': self.operation,
            'object_type': self.category,
            'dn': self.dn,
        }
        if self.entry is not None:
            change['object'] = json.loads(self.entry.entry_to_json())
        return change


class IncrementalResult:
    def __init__(self, baseline, base_dn, from_usn, to_usn, changes,
                 entries_by_type, inventory_count, generated_at):
        self.baseline = baseline
        self.base_dn = base_dn
        self.from_usn = from_usn
        self.to_usn = to_usn
        self.changes = changes
        self.entries_by_type = entries_by_type
        self.inventory_count = inventory_count
        self.generated_at = generated_at

    def summary(self):
        summary = {'add': 0, 'modify': 0, 'delete': 0}
        for change in self.changes:
            summary[change.operation] = summary.get(change.operation, 0) + 1
        return summary


class IncrementalCollector:
    def __init__(self, connection, base_dn, state_path, page_size=DEFAULT_PAGE_SIZE,
                 minimal=False, reset=False, warn=None, allow_delete_check=True):
        if page_size is None or int(page_size) <= 0:
            raise ValueError('page_size must be a positive integer')
        self.connection = connection
        self.base_dn = base_dn
        self.state_path = os.path.abspath(state_path)
        self.stage_path = self.state_path + '.stage'
        self.staging = StagingLog(self.stage_path)
        self.page_size = int(page_size)
        self.minimal = minimal
        self.reset = reset
        self.warn = warn or (lambda message: None)
        self.allow_delete_check = allow_delete_check
        self.identity = connection_identity(connection)

    def _new_state(self):
        return {
            'version': STATE_VERSION,
            'base_dn': self.base_dn,
            'source': self.identity,
            'last_usn': 0,
            'baseline_complete': False,
            'last_run': None,
            'inventory': {},
            'pending': None,
        }

    def _load_state(self):
        if self.reset:
            self.staging.clear()
            if os.path.exists(self.state_path):
                os.unlink(self.state_path)
            return self._new_state()
        if not os.path.exists(self.state_path):
            self.staging.clear()
            return self._new_state()
        try:
            state = _read_json(self.state_path)
        except (ValueError, OSError) as error:
            raise IncrementalStateError(
                'could not read incremental state %s: %s; use --reset-state '
                'to start a new baseline' % (self.state_path, error)
            )
        if state.get('version') != STATE_VERSION:
            raise IncrementalStateError(
                'unsupported incremental state version in %s; use '
                '--reset-state to start a new baseline' % self.state_path
            )
        return state

    def _reset_for_source(self, state):
        state.clear()
        state.update(self._new_state())
        self.staging.clear()
        return state

    def _prepare(self, state):
        if state.get('base_dn', '').lower() != self.base_dn.lower():
            raise IncrementalStateError(
                'incremental state belongs to %s, not %s; use another state '
                'file or --reset-state' % (state.get('base_dn'), self.base_dn)
            )
        if self.identity and state.get('source') and state['source'] != self.identity:
            self.warn(
                'uSNChanged checkpoints are DC-specific and the saved source '
                'differs; starting a new baseline'
            )
            state = self._reset_for_source(state)
        elif self.identity and not state.get('source'):
            state['source'] = self.identity

        pending = state.get('pending')
        if pending:
            if pending.get('stage') != self.stage_path or not self.staging.exists():
                self.warn('staged incremental data is missing; restarting the current run')
                state['pending'] = None
                _atomic_json_write(self.state_path, state)
                self.staging.clear()
                pending = None
            else:
                return state, pending

        baseline = not state.get('baseline_complete', False)
        start_usn = 0 if baseline else int(state.get('last_usn', 0))
        pending = {
            'mode': 'baseline' if baseline else 'incremental',
            'start_usn': start_usn,
            'inclusive': baseline,
            'phase': 'objects',
            'object_usn': start_usn,
            'deleted_usn': start_usn,
            'cookie': None,
            'objects_complete': False,
            'deleted_complete': baseline or not self.allow_delete_check,
            'stage': self.stage_path,
            'started_at': _utc_timestamp(),
        }
        self.staging.reset()
        state['pending'] = pending
        _atomic_json_write(self.state_path, state)
        return state, pending

    def _attributes(self):
        if not self.minimal:
            return [ldap3.ALL_ATTRIBUTES, 'uSNChanged', 'objectGUID', 'isDeleted']
        attributes = []
        for name in (
            INCREMENTAL_ATTRIBUTES +
            [
                'cn', 'name', 'sAMAccountName', 'dNSHostName', 'operatingSystem',
                'operatingSystemServicePack', 'operatingSystemVersion',
                'lastLogon', 'userAccountControl', 'whenCreated', 'whenChanged',
                'objectSid', 'description', 'memberOf', 'primaryGroupId',
                'pwdLastSet', 'servicePrincipalName', 'member',
            ] +
            POLICY_ATTRIBUTES +
            TRUST_ATTRIBUTES
        ):
            if name not in attributes:
                attributes.append(name)
        return attributes

    def _search(self, search_filter, attributes, cookie=None, deleted=False):
        controls = None
        if deleted:
            controls = [(SHOW_DELETED_OID, True, None)]
        paged_cookie = _cookie_from_text(cookie)
        self.connection.search(
            self.base_dn,
            search_filter,
            attributes=attributes,
            paged_size=self.page_size,
            paged_cookie=paged_cookie,
            controls=controls,
        )

        result = getattr(self.connection, 'result', None) or {}
        result_code = result.get('result', 0)
        try:
            result_code = int(result_code)
        except (TypeError, ValueError):
            pass
        if result_code not in (None, 0):
            return False, RuntimeError(
                'LDAP search failed: %s' % result.get('description', result_code)
            ), None, []
        entries = list(getattr(self.connection, 'entries', []) or [])
        return True, None, _response_cookie(result), entries

    def _scan_phase(self, state, pending, deleted=False):
        phase_name = 'deleted' if deleted else 'objects'
        usn_key = 'deleted_usn' if deleted else 'object_usn'
        start_usn = int(pending['start_usn'])
        if deleted:
            search_filter = '(&(isDeleted=TRUE)(uSNChanged>%d))' % start_usn
        else:
            operator = '>=' if pending.get('inclusive') else '>'
            search_filter = '(&%s(uSNChanged%s%d))' % (
                OBJECT_FILTER, operator, start_usn
            )
        attributes = self._attributes()
        cookie = pending.get('cookie')
        restarted = False

        while True:
            success, error, next_cookie, entries = self._search(
                search_filter, attributes, cookie, deleted=deleted
            )
            if not success and cookie and not restarted:
                self.warn(
                    'paged checkpoint for %s could not be resumed; restarting '
                    'this phase from uSNChanged %d' % (phase_name, start_usn)
                )
                cookie = None
                pending['cookie'] = None
                _atomic_json_write(self.state_path, state)
                restarted = True
                continue
            if not success:
                if deleted:
                    self.warn(
                        'could not query deleted objects; deletion detection '
                        'was skipped for this run: %s' % error
                    )
                    pending['deleted_complete'] = True
                    pending['cookie'] = None
                    _atomic_json_write(self.state_path, state)
                    return
                raise error

            records = []
            phase_usn = int(pending[usn_key])
            for entry in entries:
                record = entry_to_record(entry, deleted=deleted)
                if record['category'] is None and not deleted:
                    continue
                phase_usn = max(phase_usn, record['usn'])
                records.append(record)
            if records:
                self.staging.append(records)

            pending[usn_key] = phase_usn
            pending['cookie'] = next_cookie
            if not next_cookie:
                pending['%s_complete' % phase_name] = True
            _atomic_json_write(self.state_path, state)
            if not next_cookie:
                return
            cookie = next_cookie

    def _deduplicate(self):
        by_key = {}
        for record in self.staging.records():
            current = by_key.get(record['key'])
            if current is None or record.get('usn', 0) >= current.get('usn', 0):
                by_key[record['key']] = record
        return list(by_key.values())

    def _finish(self, state, pending):
        records = self._deduplicate()
        records.sort(key=lambda record: (
            (record.get('dn') or '').lower(), record.get('key') or ''
        ))
        baseline = pending['mode'] == 'baseline'
        inventory = state.get('inventory', {})
        changes = []
        entries_by_type = dict(
            (name, []) for name in ('users', 'computers', 'groups', 'policy', 'trusts')
        )

        if baseline:
            inventory = {}
            for record in records:
                if record.get('deleted') or not record.get('category'):
                    continue
                digest = _record_digest(record['attributes'])
                inventory[record['key']] = {
                    'dn': record['dn'],
                    'category': record['category'],
                    'digest': digest,
                }
                entry = record_to_entry(record)
                entries_by_type[record['category']].append(entry)
        else:
            for record in records:
                key = record['key']
                previous = inventory.get(key)
                if record.get('deleted'):
                    if previous is None:
                        continue
                    changes.append(DiffChange(
                        'delete', previous.get('category', 'unknown'),
                        previous.get('dn', record['dn'])
                    ))
                    inventory.pop(key, None)
                    continue
                category = record.get('category')
                if not category:
                    continue
                digest = _record_digest(record['attributes'])
                if previous is None:
                    operation = 'add'
                elif previous.get('digest') != digest:
                    operation = 'modify'
                else:
                    inventory[key] = {
                        'dn': record['dn'],
                        'category': category,
                        'digest': digest,
                    }
                    continue
                entry = record_to_entry(record)
                changes.append(DiffChange(operation, category, record['dn'], entry))
                entries_by_type[category].append(entry)
                inventory[key] = {
                    'dn': record['dn'],
                    'category': category,
                    'digest': digest,
                }

        to_usn = max(
            int(pending.get('start_usn', 0)),
            int(pending.get('object_usn', 0)),
            int(pending.get('deleted_usn', 0)),
        )
        generated_at = _utc_timestamp()
        state.update({
            'last_usn': to_usn,
            'baseline_complete': True,
            'last_run': generated_at,
            'inventory': inventory,
            'pending': None,
        })
        _atomic_json_write(self.state_path, state)
        self.staging.clear()
        return IncrementalResult(
            baseline=baseline,
            base_dn=self.base_dn,
            from_usn=int(pending.get('start_usn', 0)),
            to_usn=to_usn,
            changes=changes,
            entries_by_type=entries_by_type,
            inventory_count=len(inventory),
            generated_at=generated_at,
        )

    def run(self):
        state = self._load_state()
        state, pending = self._prepare(state)

        if not pending.get('objects_complete'):
            self._scan_phase(state, pending, deleted=False)

        if not pending.get('deleted_complete'):
            self._scan_phase(state, pending, deleted=True)

        return self._finish(state, pending)
