"""Only fixed, bounded commands against the two explicitly owned lab containers."""

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from mini_siem.feature_contract import read_contract as read_json
from mini_siem.evaluation.inventory import utc_timestamp
from mini_siem.lab.isolation import COMPOSE, SERVICES, validate_config, validate_state
from mini_siem.lab.telemetry import ADAPTER_VERSION, canonical, csv_bytes, inventory_for_collection, normalize, quality_summary, sha256


SCENARIOS={'success':('good',1,0),'single-failure':('wrong',1,255),'short-failure-sequence':('wrong',3,255),'session-logout':('good',1,0)}


def now():return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def execute(command, timeout=15, binary=False):
    result=subprocess.run(command,capture_output=True,text=not binary,timeout=timeout)
    if result.returncode:raise ValueError('Local tool operation failed')
    return result.stdout


def local_host():
    if any(os.environ.get(key) for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','COMPOSE_PROJECT_NAME','COMPOSE_FILE','LAB_KEYS_DIR','LAB_UID','LAB_GID')):
        raise ValueError('Docker endpoint environment overrides are unsupported')
    endpoint=execute(['docker','context','inspect','--format','{{.Endpoints.docker.Host}}']).strip()
    daemon=execute(['docker','info','--format','{{.ID}}']).strip()
    if not endpoint.startswith('unix://') or not daemon:raise ValueError('Only local Unix Docker sockets are supported')
    return endpoint,daemon


def configuration_digest():
    paths=[COMPOSE, *sorted((COMPOSE.parent/'server').iterdir()), *sorted((COMPOSE.parent/'client').iterdir())]
    return sha256(canonical({str(path.relative_to(COMPOSE.parent)):sha256(path.read_bytes()) for path in paths if path.is_file()}))


def env_text(state):
    return f"COMPOSE_PROJECT_NAME={state['environment_id']}\nLAB_KEYS_DIR={state['keys_dir']}\nLAB_UID={state['uid']}\nLAB_GID={state['gid']}\n"


def load_state(runtime):
    root=Path(runtime).resolve()
    state=read_json(root/'state.json')
    if set(state)!={'environment_id','keys_dir','uid','gid','created_at_utc','configuration_sha256','operator_isolated_host_attestation'} or not re.fullmatch(r'mini-siem-ssh-[a-f0-9]{12}',state['environment_id']):
        raise ValueError('Unrecognized lab runtime')
    if state['operator_isolated_host_attestation'] is not True or state['configuration_sha256']!=configuration_digest():
        raise ValueError('Host isolation attestation or reviewed configuration is absent/changed')
    keys=root/'keys'
    if keys.is_symlink() or any((keys/name).is_symlink() or not (keys/name).is_file() for name in ('good','good.pub','wrong','wrong.pub')):
        raise ValueError('Prepared keys must be real local files, not symlinks')
    if any((keys/name).stat().st_mode & 0o077 for name in ('good','wrong')):
        raise ValueError('Private key permissions must remain owner-only')
    if Path(state['keys_dir'])!=root/'keys' or not all(type(state[key]) is int and state[key]>=0 for key in ('uid','gid')) or (root/'lab.env').read_text()!=env_text(state):
        raise ValueError('Runtime identity/environment changed')
    return root,state


def compose(root,*args):
    return ['docker','compose','--env-file',str(root/'lab.env'),'-f',str(COMPOSE),*args]


def prepare(runtime, isolated_host_attested=False):
    if not isolated_host_attested:raise ValueError('Operator must verify host-only/disconnected VM networking before preparation')
    root=Path(runtime).resolve()
    if not re.fullmatch(r'[A-Za-z0-9_./-]+',str(root)):raise ValueError('Use a runtime path without spaces or shell metacharacters')
    validate_config(read_json(COMPOSE))
    root.mkdir(parents=True,mode=0o700,exist_ok=False)
    keys=root/'keys';keys.mkdir(mode=0o700)
    state={'environment_id':'mini-siem-ssh-'+uuid.uuid4().hex[:12],'keys_dir':str(keys),
           'uid':os.getuid(),'gid':os.getgid(),'created_at_utc':now(),
           'configuration_sha256':configuration_digest(),'operator_isolated_host_attestation':True}
    for name in ('good','wrong'):
        execute(['ssh-keygen','-q','-t','ed25519','-N','','-C','disposable-mini-siem-lab','-f',str(keys/name)])
        (keys/name).chmod(0o600)
        (keys/(name+'.pub')).chmod(0o644)
    (root/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    (root/'lab.env').write_text(env_text(state))
    return {'prepared':True,'credentials':'ephemeral key files only; never printed','software_installed':False}


def verify(runtime, require_binding=False):
    root,state=load_state(runtime)
    validate_config(read_json(COMPOSE))
    endpoint,daemon=local_host()
    # Ensure host COMPOSE_/LAB_ variables cannot override the prepared env file.
    if any(os.environ.get(key) for key in ('COMPOSE_PROJECT_NAME','COMPOSE_FILE','LAB_KEYS_DIR','LAB_UID','LAB_GID')):
        raise ValueError('Compose environment overrides are unsupported')
    containers={}
    for service in SERVICES:
        ids=execute(compose(root,'ps','-q',service)).split()
        if len(ids)!=1:raise ValueError('Exactly one running container per lab service is required')
        containers[service]=json.loads(execute(['docker','inspect',ids[0]]))[0]
    networks=containers['ssh-server']['NetworkSettings']['Networks']
    if len(networks)!=1:raise ValueError('Unexpected server networks')
    network=json.loads(execute(['docker','network','inspect',next(iter(networks))]))[0]
    validate_state(state,containers,network,daemon,endpoint)
    if require_binding:
        binding=read_json(root/'host-binding.json')
        if binding['server_container_id']!=containers['ssh-server']['Id'] or (root/'keys/known_hosts').read_text()!=binding['known_hosts']:
            raise ValueError('Host key/container binding changed; explicit trust-host required')
    return root,state,containers,daemon


def trust_host(runtime):
    root,state,containers,daemon=verify(runtime)
    if (root/'host-binding.json').exists() or (root/'keys/known_hosts').exists():raise ValueError('Host trust already exists; use a fresh lab rather than overwrite')
    public=execute(['docker','exec',containers['ssh-server']['Id'],'cat','/run/lab/ssh_host_ed25519_key.pub']).split()
    if len(public)<2 or public[0]!='ssh-ed25519':raise ValueError('Unexpected host key type')
    base64.b64decode(public[1],validate=True)
    known=f'[ssh-server]:2222 {public[0]} {public[1]}\n'
    (root/'keys/known_hosts').write_text(known)
    (root/'host-binding.json').write_text(json.dumps({'server_container_id':containers['ssh-server']['Id'],'known_hosts':known},indent=2)+'\n')
    return {'host_key_bound':True,'public_key_verification':'verified local container; no SSH host-key bypass'}


def scenario(runtime,name):
    if name not in SCENARIOS:raise ValueError('Unknown bounded lab scenario')
    root,state,containers,daemon=verify(runtime,True)
    key,attempts,expected=SCENARIOS[name]
    run={'manifest_version':1,'run_id':str(uuid.uuid4()),'scenario_id':name,'environment_id':state['environment_id'],
         'server_container_id':containers['ssh-server']['Id'],'client_container_id':containers['ssh-client']['Id'],
         'daemon_id':daemon,'test_account':'labuser','started_at_utc':now(),'ended_at_utc':None,
         'expected_authentication_result':'success' if key=='good' else 'rejection',
         'intent_is_verified_event_label':False,'event_labels_assigned':False,'actions':[],
         'evidence_references':[{'kind':'docker_container_log_stream','server_container_id':containers['ssh-server']['Id'],'collection_required':True}],
         'status':'in_progress'}
    path=root/('experiment-'+run['run_id']+'.json')
    with path.open('x') as handle:json.dump(run,handle,indent=2)
    try:
        for index in range(attempts):
            if (root/'STOP').exists():run['status']='operator_stopped';break
            _,_,current,_=verify(runtime,True)
            if any(current[service]['Id']!=containers[service]['Id'] for service in SERVICES):raise ValueError('Lab replaced during scenario')
            command=['docker','exec',containers['ssh-client']['Id'],'timeout','8s','ssh','-T','-p','2222',
                     '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
                     '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
                     '-o','NumberOfPasswordPrompts=0','-o','ConnectionAttempts=1','-o','ConnectTimeout=3',
                     '-o','ServerAliveInterval=2','-o','ServerAliveCountMax=1',
                     '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/lab-keys/known_hosts',
                     '-o','GlobalKnownHostsFile=/dev/null','-i','/lab-keys/'+key,'labuser@ssh-server','/bin/true']
            action={'attempt':index+1,'started_at_utc':now(),'ended_at_utc':None,
                    'action':'one public-key authentication and forced /bin/true session',
                    'credential_role':'authorized_disposable_key' if key=='good' else 'unauthorized_disposable_key',
                    'client_return_code':None,'matches_expected_client_return_code':False,
                    'verification':'client exit is not proof of server authentication outcome; review telemetry'}
            run['actions'].append(action)
            path.write_text(json.dumps(run,indent=2)+'\n')
            try:
                result=subprocess.run(command,capture_output=True,timeout=10)
                action['client_return_code']=result.returncode
                action['matches_expected_client_return_code']=result.returncode==expected
            finally:action['ended_at_utc']=now()
            if result.returncode!=expected:run['status']='unexpected_client_result';break
            if index+1<attempts:
                for _ in range(20):
                    if (root/'STOP').exists():break
                    time.sleep(.1)
        else:run['status']='actions_completed_pending_review'
    except KeyboardInterrupt:run['status']='operator_interrupted'
    except (ValueError,OSError,subprocess.TimeoutExpired):run['status']='aborted_pending_review'
    finally:
        run['ended_at_utc']=now()
        path.write_text(json.dumps(run,indent=2)+'\n')
    return {'scenario_id':name,'attempts_recorded':len(run['actions']),'status':run['status'],
            'event_labels_assigned':False,'training_allowed':False,'inference_allowed':False}


def validate_experiment(run,state,containers,daemon):
    if run.get('manifest_version')!=1 or run.get('scenario_id') not in SCENARIOS:
        raise ValueError('Unsupported experiment format')
    if run['environment_id']!=state['environment_id'] or run['server_container_id']!=containers['ssh-server']['Id'] or run['client_container_id']!=containers['ssh-client']['Id'] or run['daemon_id']!=daemon or run['test_account']!='labuser':
        raise ValueError('Scenario provenance does not match verified lab')
    if run['intent_is_verified_event_label'] is not False or run['event_labels_assigned'] is not False:
        raise ValueError('Scenario intent must not be promoted to event labels')
    uuid.UUID(run['run_id'])
    start,end=utc_timestamp(run['started_at_utc']),utc_timestamp(run['ended_at_utc'])
    if end<start or not isinstance(run['actions'],list) or len(run['actions'])>SCENARIOS[run['scenario_id']][1]:
        raise ValueError('Invalid scenario timing or bounds')
    for index,action in enumerate(run['actions'],1):
        if action['attempt']!=index or not start<=utc_timestamp(action['started_at_utc'])<=utc_timestamp(action['ended_at_utc'])<=end:
            raise ValueError('Invalid action chronology')
    return True


def collect(runtime,output,run_paths):
    root,state,containers,daemon=verify(runtime,True)
    target=Path(output).resolve()
    if target.exists() or target.is_relative_to(root):raise ValueError('Use a fresh collection directory outside runtime')
    server_id=containers['ssh-server']['Id']
    experiments=[]
    archived_experiments={}
    for path in run_paths:
        content=Path(path).read_bytes();run=json.loads(content)
        validate_experiment(run,state,containers,daemon)
        archived_experiments['experiment-'+run['run_id']+'.json']=content
        experiments.append({'run_id':run['run_id'],'manifest_sha256':sha256(content),'scenario_id':run['scenario_id'],
                            'started_at_utc':run['started_at_utc'],'ended_at_utc':run['ended_at_utc'],
                            'label_status':'intent_only_unverified_event_outcomes'})
    if len({run['run_id'] for run in experiments})!=len(experiments):raise ValueError('Duplicate scenario references')
    started=now()
    result=subprocess.run(['docker','logs','--timestamps',server_id],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15)
    if result.returncode:raise ValueError('Docker log collection failed')
    raw=result.stdout
    _,_,after,_=verify(runtime,True)
    if after['ssh-server']['Id']!=server_id:raise ValueError('Server changed during collection')
    provenance={'collection_id':str(uuid.uuid4()),'environment_id':state['environment_id'],
                'server_container_id':server_id,'daemon_id':daemon,'test_run_ids':[run['run_id'] for run in experiments]}
    records=normalize(raw,provenance);normalized=csv_bytes(records)
    manifest={'collection_manifest_version':1,'adapter_version':ADAPTER_VERSION,'configuration_sha256':state['configuration_sha256'],
              'server_image_id':containers['ssh-server']['Image'],'client_image_id':containers['ssh-client']['Image'],'provenance':provenance,'experiments':experiments,
              'collection_started_at_utc':started,'collection_finished_at_utc':now(),
              'container_started_at':containers['ssh-server']['State']['StartedAt'],
              'raw_sha256':sha256(raw),'normalized_sha256':sha256(normalized),
              'source':'docker logs --timestamps of verified local lab sshd; export may include prior server lifetime records',
              'limitations':['processing/engine times are not original event times','bounded rotating log retention can omit earlier records; export completeness not certified'],
              'event_labels_assigned':False,'training_allowed':False,'inference_allowed':False}
    inventory=inventory_for_collection(records,normalized,raw,manifest)
    target.mkdir(parents=True,mode=0o700,exist_ok=False)
    if archived_experiments:
        archive=target/'experiments';archive.mkdir(mode=0o700)
        for name,content in archived_experiments.items():(archive/name).write_bytes(content)
    (target/'raw-docker.log').write_bytes(raw);(target/'events.csv').write_bytes(normalized)
    for name,value in (('collection.json',manifest),('inventory.json',inventory),('quality.json',quality_summary(records))):
        (target/name).write_text(json.dumps(value,indent=2)+'\n')
    return quality_summary(records)
