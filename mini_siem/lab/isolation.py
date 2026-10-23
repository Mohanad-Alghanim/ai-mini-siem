"""Fail-closed static and Docker-state isolation checks for the fixed lab."""

from ipaddress import ip_address, ip_network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / 'lab/ssh/compose.json'
SERVICES = ('ssh-server','ssh-client')
SERVER_CAPS = {'SETUID','SETGID','SYS_CHROOT'}


def validate_config(config):
    if set(config) != {'services','networks'} or set(config['services']) != set(SERVICES):
        raise ValueError('Unexpected lab configuration')
    if config['networks'] != {'ssh-internal':{'driver':'bridge','internal':True,'enable_ipv6':False}}:
        raise ValueError('Only the private internal bridge is allowed')
    for name,service in config['services'].items():
        allowed={'read_only','cap_drop','security_opt','pids_limit','mem_limit','cpus','networks','restart','ipc','logging','labels','build','cap_add','tmpfs','volumes','user','image'}
        if set(service)-allowed:raise ValueError('Unreviewed service setting')
        forbidden={'ports','network_mode','privileged','pid','devices','extra_hosts','volumes_from','external_links','links','env_file','environment','entrypoint','command','hostname','container_name'}
        if forbidden & set(service):
            raise ValueError('Unsafe/overridden service configuration')
        if service['networks'] != ['ssh-internal'] or service['read_only'] is not True or service['cap_drop'] != ['ALL'] or service['security_opt'] != ['no-new-privileges:true']:
            raise ValueError('Required isolation controls missing')
        if service['image']!='mini-siem-local/'+('ssh-server' if name=='ssh-server' else 'ssh-client')+':task010':
            raise ValueError('Unexpected image tag')
        if service['pids_limit']!=64 or service['mem_limit']!='128m' or service['cpus']!=0.5 or service['restart']!='no' or service['ipc']!='private':
            raise ValueError('Fixed conservative resource/runtime limits required')
        caps=set(service.get('cap_add',[]))
        if caps != (SERVER_CAPS if name=='ssh-server' else set()):
            raise ValueError('Unexpected privileges')
        expected=['${LAB_KEYS_DIR:?prepare required}/good.pub:/lab/authorized_key:ro'] if name=='ssh-server' else ['${LAB_KEYS_DIR:?prepare required}:/lab-keys:ro']
        build={'context':'./server'} if name=='ssh-server' else {'context':'./client','args':{'LAB_UID':'${LAB_UID:?prepare required}','LAB_GID':'${LAB_GID:?prepare required}'}}
        if service['volumes'] != expected or service['build'] != build:
            raise ValueError('Unexpected host mounts/build context')
        if name=='ssh-client' and service['user'] != '${LAB_UID:?prepare required}:${LAB_GID:?prepare required}':
            raise ValueError('Client must use prepared operator UID/GID')
    return True


def validate_state(state, containers, network, daemon_id, endpoint):
    """No live probes outside the two-container network. Host routing is an operator prerequisite."""
    if not endpoint.startswith('unix://') or not daemon_id:
        raise ValueError('Only a known local Unix-socket Docker daemon is supported')
    if network.get('Driver')!='bridge' or network.get('Internal') is not True or network.get('EnableIPv6') is not False:
        raise ValueError('Runtime network is not the isolated bridge')
    if network.get('Labels',{}).get('com.docker.compose.project') != state['environment_id']:
        raise ValueError('Network ownership mismatch')
    subnets=[ip_network(item['Subnet']) for item in network.get('IPAM',{}).get('Config',[]) if item.get('Subnet')]
    private=[ip_network(value) for value in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    if len(subnets)!=1 or subnets[0].version!=4 or not any(subnets[0].subnet_of(net) for net in private):
        raise ValueError('Network must use one RFC1918 IPv4 subnet')
    ids={container['Id'] for container in containers.values()}
    if len(ids)!=2 or set(network.get('Containers',{}))!=ids:
        raise ValueError('Unexpected or missing network peers')
    for name,container in containers.items():
        config,host=container['Config'],container['HostConfig']
        labels=config.get('Labels',{})
        if labels.get('com.docker.compose.project')!=state['environment_id'] or labels.get('com.docker.compose.service')!=name or labels.get('org.mini-siem.lab')!='ssh-task-010' or labels.get('org.mini-siem.environment')!=state['environment_id']:
            raise ValueError('Container ownership mismatch')
        if not container['State'].get('Running'):
            raise ValueError('Both lab containers must be running')
        endpoints=container['NetworkSettings']['Networks']
        if set(endpoints)!={network['Name']} or endpoints[network['Name']].get('NetworkID')!=network['Id']:
            raise ValueError('Container has unexpected networking')
        address=ip_address(endpoints[network['Name']]['IPAddress'])
        if address not in subnets[0]:raise ValueError('Endpoint outside isolated subnet')
        if host.get('Devices') or host.get('DeviceRequests') or host.get('ExtraHosts') or host.get('Links'):
            raise ValueError('Unexpected host integration')
        if host.get('NetworkMode') in ('host','none','default') or host.get('Privileged') or host.get('PublishAllPorts') or host.get('PortBindings') or host.get('PidMode') or host.get('UsernsMode')=='host' or host.get('IpcMode')!='private':
            raise ValueError('Unsafe runtime host/network mode')
        if any(container['NetworkSettings'].get('Ports',{}).values()):
            raise ValueError('Published ports are forbidden')
        if not host.get('ReadonlyRootfs') or 'ALL' not in (host.get('CapDrop') or []) or 'no-new-privileges:true' not in (host.get('SecurityOpt') or []):
            raise ValueError('Runtime security controls missing')
        caps={value.removeprefix('CAP_') for value in (host.get('CapAdd') or [])}
        if caps != (SERVER_CAPS if name=='ssh-server' else set()):
            raise ValueError('Unexpected runtime capabilities')
        expected_source=Path(state['keys_dir']) / 'good.pub' if name=='ssh-server' else Path(state['keys_dir'])
        destination='/lab/authorized_key' if name=='ssh-server' else '/lab-keys'
        binds=[mount for mount in container.get('Mounts',[]) if mount['Type']=='bind']
        if len(binds)!=1 or binds[0].get('RW') or Path(binds[0]['Source']).resolve()!=expected_source.resolve() or binds[0]['Destination']!=destination:
            raise ValueError('Unexpected host filesystem exposure')
        if any(mount['Type'] not in ('bind','tmpfs') for mount in container.get('Mounts',[])):
            raise ValueError('Unexpected mounts')
        if name=='ssh-client' and config.get('User')!=f"{state['uid']}:{state['gid']}":
            raise ValueError('Client identity changed')
    return True
