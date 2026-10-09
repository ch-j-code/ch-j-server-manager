"""Fixed Linux editor protocol. Invoked in memory; never installed on the server.

All path walks use directory descriptors and O_NOFOLLOW. The working copy is
retained even after replacement: only a subsequent confirmed cleanup removes it.
"""
import base64
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import sys

LIMIT = 25 * 1024 * 1024
REPLACED = False


def fail(code):
    raise ValueError(code)


def directory(path, privileged=False):
    if not path.startswith('/') or '\x00' in path or any(p in ('.', '..') for p in path.split('/')):
        fail('FILE_UNSAFE_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        def trusted(value):
            s = os.fstat(value)
            if privileged and (s.st_uid != 0 or s.st_mode & 0o022 or 'system.posix_acl_access' in os.listxattr(value)):
                fail('FILE_UNSAFE_PRIVILEGED_DIRECTORY')
        trusted(fd)
        for part in filter(None, path.split('/')):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            trusted(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular(parent, name, owner=None, private=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or (owner is not None and s.st_uid != owner) or (private and stat.S_IMODE(s.st_mode) != 0o600):
        os.close(fd)
        fail('FILE_UNSAFE_TYPE_OR_LINK')
    return fd


def attributes(fd):
    # Linux ACLs, capabilities and SELinux labels are extended attributes too.
    # Fail closed if any attribute cannot be read or reproduced.
    return {k: base64.b64encode(os.getxattr(fd, k)).decode('ascii') for k in sorted(os.listxattr(fd))}


def snapshot(fd):
    before = os.fstat(fd)
    if before.st_size > LIMIT:
        fail('FILE_TOO_LARGE')
    os.lseek(fd, 0, os.SEEK_SET)
    pieces = []
    length = 0
    while True:
        piece = os.read(fd, min(65536, LIMIT + 1 - length))
        if not piece:
            break
        pieces.append(piece)
        length += len(piece)
        if length > LIMIT:
            fail('FILE_TOO_LARGE')
    data = b''.join(pieces)
    xattrs = attributes(fd)
    after = os.fstat(fd)
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        fail('FILE_CONFLICT')
    meta = dict(dev=after.st_dev, ino=after.st_ino, uid=after.st_uid, gid=after.st_gid,
                mode=stat.S_IMODE(after.st_mode), size=after.st_size,
                mtimeNs=str(after.st_mtime_ns), ctimeNs=str(after.st_ctime_ns), xattrs=xattrs,
                hash=hashlib.sha256(data).hexdigest())
    return data, meta


def target(path, privileged=False):
    parent, name = os.path.split(path)
    if not name or name in ('.', '..'):
        fail('FILE_UNSAFE_PATH')
    d = directory(parent, privileged)
    try:
        return d, name, regular(d, name)
    except BaseException:
        os.close(d)
        raise


def workspace(uid=None):
    uid = os.getuid() if uid is None else uid
    home = pwd.getpwuid(uid).pw_dir
    h = directory(home)
    try:
        hs = os.fstat(h)
        if hs.st_uid != uid or hs.st_mode & 0o022 or 'system.posix_acl_access' in os.listxattr(h):
            fail('FILE_UNSAFE_WORKSPACE')
        try:
            os.mkdir('ch-j-sm', 0o700, dir_fd=h)
        except FileExistsError:
            pass
        d = os.open('ch-j-sm', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=h)
        s = os.fstat(d)
        if s.st_uid != uid:
            os.close(d)
            fail('FILE_UNSAFE_WORKSPACE')
        os.fchmod(d, 0o700)
        return d, os.path.join(home, 'ch-j-sm'), uid
    finally:
        os.close(h)


def operation_id(value):
    if not re.fullmatch('[a-f0-9]{32}', str(value)):
        fail('FILE_INVALID_RECOVERY_ID')
    return value


def names(value):
    value = operation_id(value)
    return '.' + value + '.tmp', '.' + value + '.json'


def put_record(d, name, value):
    data = json.dumps(value).encode('ascii')
    if len(data) > 256 * 1024:
        fail('FILE_METADATA_UNSUPPORTED')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=d)
    with os.fdopen(fd, 'wb') as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.fsync(d)


def get_record(d, name, uid):
    fd = regular(d, name, uid, True)
    with os.fdopen(fd, 'rb') as inp:
        raw = inp.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        fail('FILE_INVALID_RECOVERY_RECORD')
    record = json.loads(raw)
    if not re.fullmatch('[a-f0-9]{64}', record['hash']):
        fail('FILE_INVALID_RECOVERY_RECORD')
    return record


def preserved(actual, original):
    return all(actual[k] == original[k] for k in ('uid', 'gid', 'mode', 'xattrs'))


def inspect_record(d, uid, value, include_text=False):
    tmp, journal = names(value)
    r = get_record(d, journal, uid)
    fd = regular(d, tmp, uid, True)
    try:
        data, staged = snapshot(fd)
    finally:
        os.close(fd)
    complete = staged['hash'] == r['hash']
    state = 'upload-incomplete'
    if complete:
        state = 'recovery-available'
        try:
            td, name, t = target(r['path'])
            try:
                _, current = snapshot(t)
                if current['hash'] == r['hash'] and preserved(current, r['baseline']):
                    state = 'confirmed'
                elif current != r['baseline']:
                    state = 'conflict'
            finally:
                os.close(t)
                os.close(td)
        except OSError:
            pass  # Permission denied/disconnected from target: copy remains useful.
    result = dict(recoveryId=value, path=r['path'], status=state, hash=staged['hash'], complete=complete)
    if include_text:
        if not complete:
            fail('FILE_UPLOAD_INCOMPLETE')
        result['data'] = base64.b64encode(data).decode('ascii')
    return result


def run(a):
    global REPLACED
    op = a['operation']
    if op == 'read':
        d, name, fd = target(a['path'])
        try:
            data, meta = snapshot(fd)
            return dict(data=base64.b64encode(data).decode('ascii'), baseline=meta)
        finally:
            os.close(fd)
            os.close(d)
    d, home, uid = workspace(a.get('uid') if op != 'prepare' else None)
    try:
        if op == 'identity':
            return dict(uid=uid)
        if op == 'prepare':
            tmp, journal = names(a['id'])
            put_record(d, journal, dict(path=a['path'], baseline=a['baseline'], hash=a['hash']))
            return dict(temporary=home + '/' + tmp, uid=uid, recoveryId=a['id'])
        if op == 'list':
            results = []
            for name in sorted(os.listdir(d))[:10000]:
                if re.fullmatch(r'\.[a-f0-9]{32}\.json', name):
                    try:
                        results.append(inspect_record(d, uid, name[1:-5]))
                    except (OSError, ValueError, KeyError):
                        results.append(dict(recoveryId=name[1:-5], status='inspection-unavailable'))
            return dict(items=results)
        tmp, journal = names(a['id'])
        if op in ('inspect', 'cleanup'):
            result = inspect_record(d, uid, a['id'], op == 'inspect')
            if op == 'cleanup':
                if result['status'] != 'confirmed':
                    fail('FILE_RESULT_UNCONFIRMED')
                os.unlink(tmp, dir_fd=d)
                os.unlink(journal, dir_fd=d)
                os.fsync(d)
            return result
        if op != 'finalize':
            fail('FILE_INVALID_OPERATION')
        source = regular(d, tmp, uid, True)
        try:
            data, staged = snapshot(source)
            if staged['hash'] != a['hash']:
                fail('FILE_UPLOAD_INCOMPLETE')
            os.fsync(source)
            td, name, old = target(a['path'], os.geteuid() == 0)
            destination = '.chj-save-' + secrets.token_hex(16) + '.tmp'
            created = False
            try:
                fcntl.flock(old, fcntl.LOCK_EX | fcntl.LOCK_NB)
                _, baseline = snapshot(old)
                if baseline != a['baseline']:
                    fail('FILE_CONFLICT')
                # Copying a content/inode-bound integrity signature would leave
                # invalid security metadata. Re-signing requires a separate flow.
                if set(baseline['xattrs']) & {'security.ima', 'security.evm'}:
                    fail('FILE_METADATA_UNSUPPORTED')
                dest = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=td)
                created = True
                try:
                    # Write fully before applying security metadata (capabilities
                    # and setuid bits can be cleared by writes or chown).
                    with os.fdopen(os.dup(dest), 'wb') as out:
                        out.write(data)
                        out.flush()
                    ds = os.fstat(dest)
                    if (ds.st_uid, ds.st_gid) != (baseline['uid'], baseline['gid']):
                        os.fchown(dest, baseline['uid'], baseline['gid'])
                    os.fchmod(dest, baseline['mode'])
                    for key in os.listxattr(dest):
                        if key not in baseline['xattrs']:
                            os.removexattr(dest, key)
                    for key, value in baseline['xattrs'].items():
                        os.setxattr(dest, key, base64.b64decode(value))
                    _, ready = snapshot(dest)
                    if ready['hash'] != a['hash'] or not preserved(ready, baseline):
                        fail('FILE_METADATA_UNSUPPORTED')
                    os.fsync(dest)
                    # Detect writes, chmod/chown, link changes and path replacement
                    # while preparing. flock serializes cooperating editor saves.
                    _, current = snapshot(old)
                    linked = os.stat(name, dir_fd=td, follow_symlinks=False)
                    if current != baseline or linked.st_ino != baseline['ino'] or linked.st_dev != baseline['dev'] or linked.st_nlink != 1:
                        fail('FILE_CONFLICT')
                    os.replace(destination, name, src_dir_fd=td, dst_dir_fd=td)
                    REPLACED = True
                    created = False
                    os.fsync(td)
                    check_dir, check_name, verified = target(a['path'])
                    try:
                        _, final = snapshot(verified)
                    finally:
                        os.close(verified)
                        os.close(check_dir)
                    if final['ino'] != ready['ino'] or final['hash'] != a['hash'] or not preserved(final, baseline):
                        fail('FILE_RESULT_UNCONFIRMED')
                    return dict(status='saved', baseline=final, hash=final['hash'])
                finally:
                    os.close(dest)
            finally:
                if created:
                    try:
                        os.unlink(destination, dir_fd=td)
                    except OSError:
                        pass
                os.close(old)
                os.close(td)
        finally:
            os.close(source)
    finally:
        os.close(d)


try:
    if sys.platform != 'linux':
        fail('FILE_LINUX_REQUIRED')
    print(json.dumps(dict(ok=True, value=run(json.loads(sys.argv[1])))))
except BlockingIOError:
    print(json.dumps(dict(ok=False, code='FILE_CONFLICT')))
except PermissionError:
    print(json.dumps(dict(ok=False, code='FILE_RESULT_UNKNOWN' if REPLACED else 'FILE_PERMISSION_DENIED')))
except FileNotFoundError:
    print(json.dumps(dict(ok=False, code='FILE_RESULT_UNKNOWN' if REPLACED else 'FILE_NOT_FOUND')))
except OSError as e:
    code = 'FILE_UNSAFE_PATH' if e.errno in (errno.ELOOP, errno.ENOTDIR) else 'FILE_REMOTE_IO_FAILED'
    print(json.dumps(dict(ok=False, code='FILE_RESULT_UNKNOWN' if REPLACED else code)))
except (ValueError, KeyError, TypeError):
    e = sys.exc_info()[1]
    code = str(e) if re.fullmatch('FILE_[A-Z_]+', str(e)) else 'FILE_PROTOCOL_ERROR'
    print(json.dumps(dict(ok=False, code='FILE_RESULT_UNKNOWN' if REPLACED else code)))
