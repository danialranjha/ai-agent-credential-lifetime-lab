import contextlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import experiment

def check():
    suite=unittest.defaultTestLoader.discover('tests')
    result=unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    return {'tests':result.testsRun,'failures':len(result.failures),
            'errors':len(result.errors),'passed':result.wasSuccessful()}

base=check()
original=experiment.run
mutations={}
for fault in ('keep_file','deny_all'):
    with patch.object(experiment,'run',lambda fault=fault:original(fault=fault)):
        mutations[fault]=check()
report={'baseline':base,'fault_injections':mutations}
Path('artifacts').mkdir(exist_ok=True)
Path('artifacts/checks.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps(report,indent=2))
assert base['passed'] and all(r['failures']>0 and r['errors']==0 for r in mutations.values())
