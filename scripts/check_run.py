import json, os, subprocess, sys
rid=os.environ['RUN_ID'];repo=os.environ['GITHUB_REPOSITORY']
r=subprocess.run(['gh','api',f'repos/{repo}/actions/runs/{rid}'],capture_output=True,text=True,check=True)
d=json.loads(r.stdout)
if d['name']!='Daily source review' or d['conclusion']!='success' or d['head_repository']['full_name']!=repo or d['head_branch']!=os.environ.get('GITHUB_REF_NAME','main'):
    sys.exit('Untrusted candidate workflow run')
print('Candidate workflow metadata verified')
