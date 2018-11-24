from suitable import Api
import yaml


def base_setup(api):
    result = api.apt(update_cache=True)
    result = api.apt(update_cache=True)
    result = api.apt(upgrade='dist')
    pkgs = [
        'python-git',
        'iptables-persistent',
        'dnsutils',
        'fail2ban'
    ]
    for pkg in pkgs:
        result = api.apt(name=pkg)

    result = api.iptables(chain='INPUT', in_interface='lo', jump='ACCEPT')
    result = api.iptables(chain='INPUT', protocol='icmp', jump='ACCEPT')
    result = api.iptables(
        chain='INPUT',
        ctstate='ESTABLISHED,RELATED',
        jump='ACCEPT'
    )
    result = api.iptables(
        chain='INPUT',
        protocol='tcp',
        destination_port=22,
        syn='match',
        ctstate='NEW,ESTABLISHED',
        jump='ACCEPT'
    )
    result = api.iptables(chain='INPUT', policy='DROP')
    result = api.service(name='fail2ban', enabled=True, state='restarted')


def dnsmasq_setup(api, cfg):
    result = api.apt(name='dnsmasq')
    result = api.copy(
        dest='/etc/dnsmasq.conf',
        owner='root',
        mode='0644',
        content=cfg
    )
    result = api.service(name='dnsmasq', enabled=True, state='restarted')

def resolv_conf_setup(api, cfg):
    result = api.copy(
        dest='/etc/resolv.conf',
        owner='root',
        mode='0644',
        content=cfg
    )


def tinc_setup(api, tinc_cfg, salt_cfg):
    result = api.apt(name='tinc')
    result = api.file(
        dest='/etc/tinc/{}'.format(tinc_cfg['network_name']),
        owner='root',
        mode='0755',
        state='directory'
    )
    result = api.file(
        dest='/etc/tinc/{}/hosts'.format(tinc_cfg['network_name']),
        owner='root',
        mode='0755',
        state='directory'
    )
    for hostname, node in tinc_cfg['tinc_nodes'].items():
        content = '''
Name={}
Address={}
Port=655
Compression=0
Subnet={}

{}
        '''.format(node['name'],
                node['address'],
                node['subnet'],
                node['public_key'])
        result = api.copy(
            dest='/etc/tinc/{}/hosts/{}'.format(
                tinc_cfg['network_name'], node['name']
            ),
            owner='root',
            mode='0755',
            content=content)

    result = api.copy(
        dest='/etc/tinc/{}/rsa_key.priv'.format(
            salt_cfg['tinc_network_name']
        ),
        owner='root',
        mode='0600',
        content=salt_cfg['tinc_private_key']
    )

    result = api.copy(
        dest='/etc/tinc/{}/rsa_key.pub'.format(
            salt_cfg['tinc_network_name']
        ),
        owner='root',
        mode='0600',
        content=salt_cfg['tinc_public_key']
    )

    result = api.copy(
        dest='/etc/tinc/{}/tinc.conf'.format(
            salt_cfg['tinc_network_name']
        ),
        owner='root',
        mode='0600',
        content=salt_cfg['tinc_conf']
    )

    result = api.copy(
        dest='/etc/tinc/nets.boot',
        owner='root',
        mode='0600',
        content=tinc_cfg['network_name']
    )

    result = api.copy(
        dest='/etc/default/tinc',
        owner='root',
        mode='0644',
        content='EXTRA="-d -n {}"'.format(
            tinc_cfg['network_name']
        )
    )

    result = api.copy(
        dest='/etc/tinc/{}/tinc-up'.format(
            tinc_cfg['network_name']
        ),
        owner='root',
        mode='0755',
        content='''
                #!/bin/sh

                # see: https://www.tinc-vpn.org/pipermail/tinc/2017-January/004729.html
                macfile=/etc/tinc/{network_name}/address
                if [ -f $macfile ]; then
                        ip link set tinc.{network_name} address `cat $macfile`
                else
                        cat /sys/class/net/tinc.{network_name}/address >$macfile
                fi

                # https://bugs.launchpad.net/ubuntu/+source/isc-dhcp/+bug/1006937
                dhclient -4 -nw -v tinc.{network_name} -cf /etc/tinc/{network_name}/dhclient.conf -r
                dhclient -4 -nw -v tinc.{network_name} -cf /etc/tinc/{network_name}/dhclient.conf

                nohup /etc/tinc/{network_name}/fix-route >/dev/null 2>&1 &
                '''.format(network_name=tinc_cfg['network_name']))

    result = api.copy(
        dest='/etc/tinc/{}/tinc-down'.format(tinc_cfg['network_name']),
        owner='root',
        mode='0755',
        content='''
                #!/bin/sh
                dhclient -4 -nw -v tinc.{{ network_name }} -cf /etc/tinc/{{ network_name }}/dhclient.conf -r
                '''.format(network_name=tinc_cfg['network_name']))

    result = api.iptables(
        chain='INPUT',
        protocol='tcp',
        destination_port=655,
        syn='match',
        ctstate='NEW,ESTABLISHED',
        jump='ACCEPT'
    )

    result = api.iptables(
        chain='INPUT',
        protocol='udp',
        destination_port=655,
        ctstate='NEW,ESTABLISHED',
        jump='ACCEPT'
    )

    result = api.iptables(
        chain='INPUT',
        in_interface='tinc.{}'.format(tinc_cfg['network_name']),
        jump='ACCEPT'
    )

    result = api.service(name='tinc', enabled=True, state='reloaded')

    result = api.service(
        name='tinc@{}'.format(tinc_cfg['network_name']),
        enabled=True,
        state='reloaded'
    )


def salt_setup(api):
    result = api.apt_key(
        url='https://repo.saltstack.com/apt/debian/9/amd64/latest/SALTSTACK-GPG-KEY.pub')

    result = api.apt_repository(
        repo='deb http://repo.saltstack.com/apt/debian/9/amd64/latest stretch main')

    result = api.apt(update_cache=True)

    for pkg in ['salt-master',
                'salt-minion',
                'salt-ssh',
                'salt-syndic',
                'salt-cloud',
                'salt-api']:
        result = api.apt(name=pkg)

    result = api.service(name='salt-master', enabled=True, state='restarted')


def role_saltmaster(api, host_cfg, tinc_cfg):
    base_setup(api)
    resolv_conf_setup(api, host_cfg['resolv_conf'])
    dnsmasq_setup(api, host_cfg['dnsmasq_conf'])
    tinc_setup(api, tinc_cfg, host_cfg)
    salt_setup(api)


with open('config.yaml', 'r') as f:
    CFG = dict(yaml.load(f))

tinc_cfg = CFG['tinc']
hosts = CFG['hosts']

for _, host_cfg in hosts.items():
    if host_cfg['role'] == 'saltmaster':
        api = Api(host_cfg['hostname'], remote_user=host_cfg['remote_user'])
        role_saltmaster(api, host_cfg, tinc_cfg )
