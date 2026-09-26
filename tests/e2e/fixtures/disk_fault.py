"""Bounded ext4 fault images. Never allocate on the host/root filesystem."""
from contextlib import contextmanager
from pathlib import Path
import errno
import os
import shutil
import subprocess
import tempfile
import time


@contextmanager
def disk_image(*, inodes=512):
    # Hosted runners keep tool directories under /opt writable by the runner.
    # Cache deletion requires an entirely root-owned, non-writable ancestry.
    base = Path('/var/lib/a4diag-remediation-lab')
    assert os.uname().nodename == 'a4diag-remediation-test'
    root = Path(tempfile.mkdtemp(prefix='disk-fault-', dir=base))
    image, mount = root/'bounded.ext4', root/'fs'
    mount.mkdir()
    with image.open('wb') as stream:
        stream.truncate(64*1024*1024)
    subprocess.run(['/usr/sbin/mkfs.ext4','-q','-F','-m','0','-N',str(inodes),str(image)], check=True)
    subprocess.run(['/usr/bin/mount','-o','loop,nodev,nosuid,noexec',str(image),str(mount)],check=True)
    try:
        cache=mount/'cache'
        cache.mkdir(mode=0o700)
        yield cache
    finally:
        subprocess.run(['/usr/bin/umount',str(mount)],check=True)
        shutil.rmtree(root)


def exhaust(cache, kind):
    before=os.statvfs(cache)
    age=time.time_ns()-3600*10**9
    count=0
    while True:
        path=cache/f'filler-{count:04d}'
        try:
            with path.open('wb') as stream:
                if kind=='blocks':
                    stream.write(b'x'*(1024*1024))
                    stream.flush()
                    os.fsync(stream.fileno())
        except OSError as error:
            if error.errno!=errno.ENOSPC:
                raise
            if path.exists():
                os.utime(path,ns=(age,age))
            break
        os.utime(path,ns=(age,age))
        count+=1
        assert count<1024, 'bounded image failed to exhaust within candidate limit'
    current=os.statvfs(cache)
    # ext4 can refuse a 1 MiB write with a small unusable remainder.
    assert current.f_bavail*current.f_frsize<1024*1024 if kind=='blocks' else current.f_favail==0
    return {'available_bytes':current.f_bavail*current.f_frsize,'free_inodes':current.f_favail,
            'initial_available_bytes':before.f_bavail*before.f_frsize}
