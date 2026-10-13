#!/usr/bin/env python3
"""Compare disposable native and launchd jobs with the current helper build."""
import argparse
import base64
import json
import os
import pathlib
import plistlib
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'client'))
from api import APIError,Client

parser=argparse.ArgumentParser()
parser.add_argument('--path',default=str(pathlib.Path.home()/'Library/Mail'))
parser.add_argument('--output',type=pathlib.Path,default=root/'build/evidence/context-matrix.json')
parser.add_argument('--include-terminal',action='store_true')
args=parser.parse_args()
helper=root/'build/Mac Permissions Helper.app/Contents/MacOS/MacPermissionsHelper'
report={"path":args.path,"operation":"directory open without enumeration","contexts":{}}

def ready(client,process=None):
    for _ in range(150):
        try:return client.call('GET','/v1/status')
        except APIError:
            if process and process.poll() is not None:raise RuntimeError('Native helper exited')
            time.sleep(.03)
    raise RuntimeError('Helper did not start')

def collect(client,request):
    route='/v1/requests/'+request['id'];cursor=0;stdout=bytearray()
    for _ in range(300):
        value=client.call('GET',route+'/events?after='+str(cursor))
        for event in value['events']:
            if event['stream']=='stdout':stdout.extend(base64.b64decode(event['data']))
        cursor=value['next']
        if value.get('complete'):
            value.pop('events');value['operationResult']=json.loads(stdout);return value
        time.sleep(.03)
    client.call('POST',route+'/cancel',{});raise RuntimeError('Target timed out')

with tempfile.TemporaryDirectory(prefix='mac-permissions-context-') as tmp:
    temp=pathlib.Path(tmp); probe=temp/'probe'
    def compile_probe(version,path):
        subprocess.run(['xcrun','clang','-DMP_VERSION='+str(version),str(root/'Tests/fixtures/probe.c'),'-o',str(path)],check=True)
    compile_probe(1,probe)
    report['directTool']=json.loads(subprocess.run([str(probe),args.path],capture_output=True,text=True).stdout)
    # A bare service has no helper app in its execution ancestry.
    bare_label='dev.macpermissions.bare.'+uuid.uuid4().hex
    bare_plist=temp/(bare_label+'.plist');bare_output=temp/'bare-launchd.json'
    with bare_plist.open('wb') as file:plistlib.dump(dict(Label=bare_label,ProgramArguments=[str(probe),args.path],RunAtLoad=True,StandardOutPath=str(bare_output)),file)
    subprocess.run(['launchctl','bootstrap','gui/'+str(os.getuid()),str(bare_plist)],check=True)
    try:
        for _ in range(150):
            try:report['bareLaunchdTool']=json.loads(bare_output.read_text());break
            except (FileNotFoundError,json.JSONDecodeError):time.sleep(.03)
        if 'bareLaunchdTool' not in report:raise RuntimeError('Bare launchd tool did not finish')
    finally:subprocess.run(['launchctl','bootout','gui/'+str(os.getuid())+'/'+bare_label],check=True)
    for context in ('native','launchd'):
        state=temp/context;state.mkdir(mode=0o700)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        command=[str(helper),'--headless','--state-dir',str(state),'--port',str(port)]
        label='dev.macpermissions.verify.'+uuid.uuid4().hex;process=None;bootstrapped=False
        try:
            if context=='native':process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            else:
                plist=temp/(label+'.plist')
                with plist.open('wb') as file:plistlib.dump(dict(Label=label,AssociatedBundleIdentifiers=['dev.macpermissions.helper'],ProgramArguments=command,RunAtLoad=True),file)
                subprocess.run(['launchctl','bootstrap','gui/'+str(os.getuid()),str(plist)],check=True);bootstrapped=True
            for _ in range(150):
                if (state/'owner.token').exists():break
                time.sleep(.03)
            client=Client('http://127.0.0.1:'+str(port),str(state/'owner.token'));status=ready(client,process)
            def approve(request):return client.call('POST','/v1/requests/'+request['id']+'/approve',dict(fingerprint=request['fingerprint']))
            direct=client.call('POST','/v1/requests',dict(operation='probe',path=args.path));helper_probe=approve(direct)
            tool=client.submit(str(probe),[args.path],str(temp),{'PATH':'/usr/bin:/bin'},False);approve(tool)
            before=collect(client,tool)
            stale=client.submit(str(probe),[args.path],str(temp),{'PATH':'/usr/bin:/bin'},False)
            newer=probe.with_suffix('.new');compile_probe(2,newer);newer.replace(probe)
            try:approve(stale);updated='ERROR: stale approval was accepted'
            except APIError as error:updated=str(error)
            current=client.submit(str(probe),[args.path],str(temp),{'PATH':'/usr/bin:/bin'},False);approve(current)
            after=collect(client,current)
            report['contexts'][context]=dict(helperStatus=status,helperProbe=helper_probe['result'],childBeforeUpdate=before,staleApproval=updated,childAfterUpdate=after)
        finally:
            if bootstrapped:subprocess.run(['launchctl','bootout','gui/'+str(os.getuid())+'/'+label],check=True)
            if process:
                process.terminate();process.wait(6);process.stderr.close()
        compile_probe(1,probe)
    if args.include_terminal:
        output=root/'build/evidence/terminal-directory.json'
        if output.exists():output.unlink()
        command=root/'build/Terminal-directory-probe.command'
        persistent_probe=root/'build/fixture-probe';compile_probe(1,persistent_probe)
        command.write_text('#!/bin/zsh\n'+shlex.join([str(persistent_probe),args.path])+' > '+shlex.quote(str(output))+'\nexit\n');command.chmod(0o700)
        subprocess.run(['open','-a','Terminal',str(command)],check=True)
        terminal=None
        for _ in range(300):
            try:
                terminal=json.loads(output.read_text());break
            except (FileNotFoundError,json.JSONDecodeError):pass
            time.sleep(.03)
        report['terminal']=terminal or {'status':'unverified','reason':'Terminal did not finish the submitted document command; owner interaction may be needed.'}
args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2))
for context,value in report['contexts'].items():
    print(context+': helper errno='+str(value['helperProbe']['errno'])+', child errno='+str(value['childBeforeUpdate']['operationResult']['openErrno'])+', updated child errno='+str(value['childAfterUpdate']['operationResult']['openErrno']))
print('Saved '+str(args.output))
