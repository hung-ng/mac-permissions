#!/usr/bin/env python3
"""Create disposable files for live permission checks, without inspecting user data."""
import argparse
import os
import pathlib
import plistlib
import shlex
import subprocess
import uuid

root=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('kind',choices=['fda','app'])
parser.add_argument('--output',type=pathlib.Path)
args=parser.parse_args()
name='MacPermissionsFixture-'+uuid.uuid4().hex[:12]
if args.kind=='fda':
    # Run this from an owner context that already has access, such as an approved Terminal.
    folder=pathlib.Path.home()/'Library/Mail'/name
    folder.mkdir(mode=0o700)
    marker=folder/'probe.txt'
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as file:
        file.write('mac-permissions disposable fixture\n')
    print(marker)
else:
    app=(args.output or root/'build')/(name+'.app')
    (app/'Contents/MacOS').mkdir(parents=True)
    (app/'Contents/Resources').mkdir()
    source=app.parent/(name+'.c')
    source.write_text('int main(void) { return 0; }\n')
    try:
        subprocess.run(['xcrun','clang',str(source),'-o',str(app/'Contents/MacOS/Fixture')],check=True)
    finally:
        source.unlink()
    with (app/'Contents/Info.plist').open('wb') as file:
        plistlib.dump(dict(CFBundleIdentifier='dev.macpermissions.fixture.'+name,
            CFBundleName=name,CFBundleExecutable='Fixture',CFBundlePackageType='APPL',CFBundleVersion='1',LSUIElement=True),file)
    (app/'Contents/Resources/mac-permissions-marker').write_text('mac-permissions app fixture v1\n')
    subprocess.run(['codesign','--force','--sign','-',str(app)],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(['open','-n','-W',str(app)],check=True)
    print(app)
