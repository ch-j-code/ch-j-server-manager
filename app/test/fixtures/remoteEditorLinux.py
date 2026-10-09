"""Exercise the shipped helper against real Linux descriptors and metadata.

Only account-home lookup is redirected into an isolated test directory. No SSH,
sudo, or external server is involved in this filesystem integration fixture.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import pwd
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

source = open(sys.argv[1], encoding='utf-8').read()
scenario = sys.argv[2]

test_parent = pwd.getpwuid(os.getuid()).pw_dir if os.geteuid() == 0 else None
with tempfile.TemporaryDirectory(prefix='chj-editor-test-', dir=test_parent) as root, contextlib.ExitStack() as stack:
    home = root + '/actual home'
    if scenario == 'cross-filesystem-strategy':
        if not os.path.isdir('/dev/shm') or os.stat('/dev/shm').st_dev == os.stat(root).st_dev:
            print('No separate writable filesystem available')
            sys.exit(77)
        home = stack.enter_context(tempfile.TemporaryDirectory(prefix='chj-editor-home-', dir='/dev/shm')) + '/actual home'
    os.mkdir(home, 0o700)
    parent = root + '/target directory'
    os.mkdir(parent, 0o700)
    path = parent + '/config\' ; $(touch unsafe) `test` ü'
    original = b'original\n'
    modified = b'modified\n'
    with open(path, 'wb') as out:
        out.write(original)
    os.chmod(path, 0o6750)

    def command(request):
        captured = io.StringIO()
        with patch.object(pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=home)), patch.object(sys, 'argv', ['remoteEditor.py', json.dumps(request)]), contextlib.redirect_stdout(captured):
            exec(compile(source, 'remoteEditor.py', 'exec'), {})
        return json.loads(captured.getvalue())

    def value(request):
        result = command(request)
        assert result['ok'], result
        return result['value']

    baseline = value(dict(operation='read', path=path))['baseline']
    ident = 'a' * 32
    digest = hashlib.sha256(modified).hexdigest()
    request = dict(operation='finalize', id=ident, uid=os.getuid(), path=path, baseline=baseline, hash=digest)

    def stage(data=modified):
        prepared = value(dict(operation='prepare', id=ident, path=path, baseline=request['baseline'], hash=digest))
        fd = os.open(prepared['temporary'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        assert stat.S_IMODE(os.stat(home + '/ch-j-sm').st_mode) == 0o700
        assert stat.S_IMODE(os.stat(prepared['temporary']).st_mode) == 0o600
        return prepared['temporary']

    def intact(staged):
        assert open(path, 'rb').read() == original
        assert open(staged, 'rb').read() == modified

    if scenario == 'metadata':
        os.setxattr(path, 'user.chj-test', b'attribute')
        request['baseline'] = value(dict(operation='read', path=path))['baseline']
        staged = stage()
        result = value(request)
        final = os.stat(path)
        assert result['status'] == 'saved'
        assert final.st_uid == baseline['uid'] and final.st_gid == baseline['gid']
        assert stat.S_IMODE(final.st_mode) == 0o6750
        assert os.getxattr(path, 'user.chj-test') == b'attribute'
        assert open(path, 'rb').read() == modified
        assert open(staged, 'rb').read() == modified
        assert final.st_mtime_ns != int(baseline['mtimeNs'])
        assert value(dict(operation='inspect', id=ident))['status'] == 'confirmed'
        value(dict(operation='cleanup', id=ident))
        assert not os.path.exists(staged)
        assert not os.listdir(home + '/ch-j-sm')
    elif scenario == 'move-failure':
        staged = stage()
        with patch.object(os, 'replace', side_effect=OSError('failed rename')):
            assert not command(request)['ok']
        intact(staged)
        assert os.listdir(parent) == [os.path.basename(path)]
    elif scenario == 'disk-full':
        staged = stage()
        with patch.object(os, 'fsync', side_effect=OSError('disk full')):
            assert not command(request)['ok']
        intact(staged)
    elif scenario == 'post-rename-disconnect':
        staged = stage()
        real_replace = os.replace

        def replace(*args, **kwargs):
            real_replace(*args, **kwargs)
            # Failure to confirm after the actual rename must be reported unknown.
        real_fsync = os.fsync
        count = [0]

        def fsync(fd):
            count[0] += 1
            if count[0] == 3:
                raise OSError('lost completion')
            return real_fsync(fd)
        with patch.object(os, 'replace', replace), patch.object(os, 'fsync', fsync):
            result = command(request)
        assert result['code'] == 'FILE_RESULT_UNKNOWN', result
        assert open(path, 'rb').read() == modified
        assert open(staged, 'rb').read() == modified
        assert value(dict(operation='list'))['items'][0]['status'] == 'confirmed'
    elif scenario == 'conflict':
        staged = stage()
        with open(path, 'wb') as out:
            out.write(b'external\n')
        assert command(request)['code'] == 'FILE_CONFLICT'
        assert open(path, 'rb').read() == b'external\n'
        assert open(staged, 'rb').read() == modified
        assert value(dict(operation='inspect', id=ident))['status'] == 'conflict'
        assert command(dict(operation='cleanup', id=ident))['code'] == 'FILE_RESULT_UNCONFIRMED'
        assert os.path.exists(staged)
    elif scenario == 'upload-incomplete':
        staged = stage(b'part')
        assert command(request)['code'] == 'FILE_UPLOAD_INCOMPLETE'
        assert open(path, 'rb').read() == original
        assert value(dict(operation='list'))['items'][0]['status'] == 'upload-incomplete'
    elif scenario == 'existing-temporary':
        staged = stage()
        assert not command(dict(operation='prepare', id=ident, path=path, baseline=baseline, hash=digest))['ok']
        intact(staged)
    elif scenario in ('target-symlink', 'target-hardlink', 'target-fifo'):
        os.unlink(path)
        other = parent + '/other'
        with open(other, 'wb') as out:
            out.write(original)
        if scenario == 'target-symlink':
            os.symlink(other, path)
        elif scenario == 'target-hardlink':
            os.link(other, path)
        else:
            os.mkfifo(path)
        assert not command(dict(operation='read', path=path))['ok']
        assert open(other, 'rb').read() == original
    elif scenario == 'workspace-symlink':
        os.symlink(parent, home + '/ch-j-sm')
        assert not command(dict(operation='prepare', id=ident, path=path, baseline=baseline, hash=digest))['ok']
        assert os.listdir(parent) == [os.path.basename(path)]
    elif scenario == 'temporary-symlink':
        staged = stage()
        os.unlink(staged)
        os.symlink(path, staged)
        assert not command(request)['ok']
        assert open(path, 'rb').read() == original
    elif scenario == 'metadata-failure':
        os.setxattr(path, 'user.chj-test', b'attribute')
        request['baseline'] = value(dict(operation='read', path=path))['baseline']
        staged = stage()
        with patch.object(os, 'setxattr', side_effect=PermissionError('metadata denied')):
            assert not command(request)['ok']
        intact(staged)
    elif scenario == 'acl':
        # Linux POSIX ACL xattr format: version, followed by tag/perm/uid entries.
        acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', tag, perm, who) for tag, perm, who in [
            (1, 7, 0xffffffff), (2, 4, os.getuid() + 1), (4, 5, 0xffffffff), (16, 5, 0xffffffff), (32, 0, 0xffffffff)])
        try:
            os.setxattr(path, 'system.posix_acl_access', acl)
        except OSError:
            print('POSIX ACLs are unavailable on the test filesystem')
            sys.exit(77)
        request['baseline'] = value(dict(operation='read', path=path))['baseline']
        staged = stage()
        assert value(request)['status'] == 'saved'
        assert os.getxattr(path, 'system.posix_acl_access') == acl
        assert open(staged, 'rb').read() == modified
    elif scenario == 'concurrent-target-replacement':
        staged = stage()
        real_fsync = os.fsync
        count = [0]

        def fsync(fd):
            count[0] += 1
            if count[0] == 2:
                replacement = parent + '/external'
                with open(replacement, 'wb') as out:
                    out.write(b'external')
                os.replace(replacement, path)
            return real_fsync(fd)
        with patch.object(os, 'fsync', fsync):
            assert command(request)['code'] == 'FILE_CONFLICT'
        assert open(path, 'rb').read() == b'external'
        assert open(staged, 'rb').read() == modified
    elif scenario == 'cross-filesystem-strategy':
        staged = stage()
        assert os.stat(staged).st_dev != os.stat(path).st_dev
        real_replace = os.replace

        def replace(src, dst, **kwargs):
            assert src != staged and '/' not in src
            assert kwargs['src_dir_fd'] == kwargs['dst_dir_fd']
            return real_replace(src, dst, **kwargs)
        with patch.object(os, 'replace', replace):
            assert value(request)['status'] == 'saved'
        assert os.path.exists(staged)
    else:
        raise AssertionError('Unknown scenario: ' + scenario)

print('ok')
