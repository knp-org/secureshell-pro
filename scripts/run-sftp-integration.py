#!/usr/bin/env python3
"""Run SFTP regression tests against an ephemeral loopback-only sshd."""
import getpass
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

sshd = shutil.which('sshd')
if not sshd:
    raise SystemExit('Install openssh-server to run SFTP integration tests.')
with tempfile.TemporaryDirectory(prefix='ssp-sftp-test-') as directory:
    root = Path(directory)
    for name, password in [('host_key', ''), ('client_key', 'integration-passphrase')]:
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', password, '-f', str(root / name)], check=True)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = root / 'sshd_config'
    config.write_text(f'''ListenAddress 127.0.0.1
Port {port}
HostKey {root / 'host_key'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root / 'client_key.pub'}
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers {getpass.getuser()}
Subsystem sftp internal-sftp
''')
    with (root / 'sshd.log').open('w+') as log:
        daemon = subprocess.Popen([sshd, '-D', '-e', '-f', str(config)], stdout=log, stderr=log)
        try:
            for _ in range(50):
                if daemon.poll() is not None:
                    log.seek(0)
                    raise SystemExit(log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            env = os.environ | {'SSP_TEST_SFTP_DIR': str(root), 'SSP_TEST_SFTP_PORT': str(port), 'SSP_TEST_SFTP_USER': getpass.getuser()}
            result = subprocess.run(['cargo', 'test', '--locked', '--manifest-path', 'src-tauri/Cargo.toml', '--lib', 'isolated_sftp_server', '--', '--ignored', '--nocapture'], env=env)
            if result.returncode:
                log.seek(0)
                print(log.read())
                raise SystemExit(result.returncode)
            subprocess.run(['cargo', 'build', '--locked', '--manifest-path', 'src-tauri/Cargo.toml'], check=True)
            executable = str((Path('src-tauri/target/debug/secureshell-pro')).resolve())
            askpass_env = os.environ | {'SSP_ASKPASS_SECRET': 'integration-passphrase',
                'SSH_ASKPASS': executable, 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': ':0'}
            for prompt in ['Password:', 'Enter passphrase for key:']:
                reply = subprocess.run([executable, prompt], env=askpass_env, capture_output=True, text=True, check=True)
                assert reply.stdout == 'integration-passphrase\n'
            denied = subprocess.run([executable, 'Trust this host?'], env=askpass_env, capture_output=True, text=True)
            assert denied.returncode != 0 and not denied.stdout
            (root / 'known_hosts').write_text(f"[127.0.0.1]:{port} " + (root / 'host_key.pub').read_text())
            subprocess.run(['ssh', '-T', '-p', str(port), '-i', str(root / 'client_key'),
                '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={root / "known_hosts"}',
                '-o', 'PreferredAuthentications=publickey',
                f'{getpass.getuser()}@127.0.0.1', 'true'], env=askpass_env, check=True, timeout=20)
            print('OpenSSH encrypted-key authentication through askpass passed.')
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
