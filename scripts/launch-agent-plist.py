#!/usr/bin/env python3
"""Write a new helper job definition. Installation is a separate owner action."""
import argparse
import pathlib
import plistlib
import sys

parser=argparse.ArgumentParser()
parser.add_argument('--app',type=pathlib.Path,required=True)
parser.add_argument('--state-dir',type=pathlib.Path,required=True)
parser.add_argument('--port',type=int,default=43187)
args=parser.parse_args()
app=args.app.expanduser().resolve()
with (app/'Contents/Info.plist').open('rb') as file:
    bundle_id=plistlib.load(file)['CFBundleIdentifier']
plistlib.dump(dict(Label=bundle_id+'.agent',AssociatedBundleIdentifiers=[bundle_id],
    ProgramArguments=[str(app/'Contents/MacOS/MacPermissionsHelper'),'--headless','--state-dir',str(args.state_dir.expanduser().absolute()),'--port',str(args.port)],
    RunAtLoad=True,KeepAlive=False,ProcessType='Background'),sys.stdout.buffer)
