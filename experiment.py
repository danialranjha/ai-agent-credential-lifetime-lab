"""Contained POSIX file-lifetime assay. No real home, key, model or network."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

MARKER = 'INVENTED_NONCREDENTIAL_MARKER_42'
NOTE = 'ordinary work note'
METHODS = ('persistent', 'read_then_delete')
SCENARIOS = tuple((f'{timing}_{mode:o}', timing, mode)
                  for timing in ('before', 'after', 'held_descriptor')
                  for mode in (0o644, 0o600)) + (
    ('missing', 'missing', 0o600),
    ('ordinary_file', 'ordinary_file', 0o600),
    ('second_consumer', 'second_consumer', 0o600))

# Fixed script, fixed generated paths. No input supplied by a caller.
PROBE = '''import json,os,sys
try:
    with (os.fdopen(int(sys.argv[2]), 'r') if sys.argv[1]=='fd' else open(sys.argv[2])) as f:
        value=f.read()
    result={'status':'read','value':value}
except FileNotFoundError:
    result={'status':'missing','value':None}
result['same_user']=os.getuid()==int(sys.argv[3])
result['environment_has_marker']=any('INVENTED_NONCREDENTIAL_MARKER' in v for v in os.environ.values())
print(json.dumps(result))
'''

def run_case(name, timing, mode, method, fault=None):
    if os.name != 'posix':
        raise RuntimeError('POSIX file and descriptor semantics required')
    with tempfile.TemporaryDirectory(prefix='file-lifetime-fixture-') as td:
        root = Path(td)
        home = root / 'fixture-home'
        home.mkdir(mode=0o700)
        key = home / 'invented-marker.txt'
        note = home / 'work-note.txt'
        note.write_text(NOTE)
        if timing != 'missing':
            key.write_text(MARKER)
            key.chmod(mode)
        actual_mode = oct(stat.S_IMODE(key.stat().st_mode)) if key.exists() else None
        env = {'HOME': str(home), 'PATH': '/usr/bin:/bin'}
        trace = ['create invented fixture' if key.exists() else 'leave marker absent',
                 'replace child environment; same OS user']
        fd = None
        if timing == 'held_descriptor':
            fd = os.open(key, os.O_RDONLY)
            trace.append('open descriptor before consumer')

        def probe():
            target = note if timing == 'ordinary_file' else key
            args = ['fd', str(fd)] if fd is not None else ['path', str(target)]
            if fault == 'deny_all':
                return {'status':'missing','value':None,'same_user':True,
                        'environment_has_marker':False}
            cp = subprocess.run([sys.executable, '-I', '-c', PROBE, *args, str(os.getuid())],
                                env=env, cwd=home, text=True, capture_output=True,
                                pass_fds=() if fd is None else (fd,), check=True)
            return json.loads(cp.stdout)

        def consume():
            command = '/bin/cat "$1" 2>/dev/null'
            if method == 'read_then_delete' and fault != 'keep_file':
                command += '; /bin/rm -f "$1"'
            cp = subprocess.run(['/bin/sh','-c',command,'fixture-consumer',str(key)],
                                env=env, cwd=home, text=True, capture_output=True)
            return {'value':cp.stdout,'exit_status':cp.returncode}

        try:
            result = None
            if timing == 'before':
                result = probe()
                trace.append('reader opens pathname before consumer')
            consumer = consume()
            trace.append('consumer reads; '+('keeps file' if method=='persistent' else 'removes pathname'))
            second = None
            if timing == 'second_consumer':
                second = consume()
                trace.append('second consumer tries same pathname')
            if result is None:
                result = probe()
                trace.append('reader reads held descriptor' if fd is not None else 'reader tries pathname after consumer')
            return {'scenario':name,'method':method,'mode_at_start':actual_mode,
                    'consumer':consumer,'second_consumer':second,'reader':result,
                    'path_exists_after':key.exists(),'trace':trace}
        finally:
            if fd is not None:
                os.close(fd)

def run(fault=None):
    return {'schema':1,'scope':'Synthetic markers; actual POSIX reads; no model, provider or network',
            'fixture_count':len(SCENARIOS),'method_count':len(METHODS),
            'rows':[run_case(*s,m,fault=fault) for s in SCENARIOS for m in METHODS]}

def evidence(data):
    lines=['# File-lifetime evidence','',
           'Nine selected deterministic fixtures, two methods, eighteen rows. Not attack rates.',
           'The consumer and reader use an explicitly replaced environment and the same OS user.',
           'Both file modes are actual observed modes. A held descriptor is deliberately opened before consumption.',
           '', '| Fixture | Persistent reader | Read then delete reader |', '|---|---|---|']
    for name,_,_ in SCENARIOS:
        rows=[r for r in data['rows'] if r['scenario']==name]
        vals=[r['reader']['value'] if r['reader']['value'] is not None else '(missing)' for r in rows]
        lines.append(f'| {name} | {vals[0]} | {vals[1]} |')
    lines += ['', '## Exact paired trace', '',
              'after_600: create owned mode-0600 marker; replace child environment; consume marker; attempt later pathname read.',
              'Persistent: consumer receives marker; later reader also receives marker; pathname remains.',
              'Read then delete: consumer receives the same marker; later reader reports missing; pathname is absent.',
              '', '## Limits visible in the same run', '',
              'Before-consumption readers and readers holding an earlier descriptor receive the marker with both methods and both file modes.',
              'The ordinary work note remains readable with both methods.',
              'Missing marker: read-then-delete returns exit status 0 with empty stdout, because rm -f is the final command. Persistent cat returns 1. Exit 0 alone is not a credential-read success oracle.',
              'Second consumption: persistent returns the marker again; read-then-delete returns empty stdout with status 0. This assay does not implement or verify any credential cache.',
              '', 'No timing race, live model, deployed workflow, isolation boundary, provider request or real secret was tested.']
    return '\n'.join(lines)+'\n'

if __name__ == '__main__':
    data=run()
    p=Path(__file__).resolve().parent/'artifacts'
    p.mkdir(exist_ok=True)
    (p/'run.json').write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    (p/'evidence.md').write_text(evidence(data))
    print('Recorded 9 paired fixtures / 18 rows in artifacts/run.json')
