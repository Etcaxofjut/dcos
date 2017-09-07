import collections
import json
import logging
import random
from subprocess import check_output

import pytest
import requests
import retrying

import test_helpers
from dcos_test_utils import marathon


log = logging.getLogger(__name__)

GLOBAL_PORT_POOL = collections.defaultdict(lambda: list(range(10000, 30000)))


def unused_port(network):
    global GLOBAL_PORT_POOL
    return GLOBAL_PORT_POOL[network].pop(random.choice(range(len(GLOBAL_PORT_POOL[network]))))


def lb_enabled():
    return test_helpers.expanded_config['enable_lb'] == 'true'


@retrying.retry(wait_fixed=2000,
                stop_max_delay=5 * 60 * 1000,
                retry_on_result=lambda ret: ret is None)
def ensure_routable(cmd, host, port):
    proxy_uri = 'http://{}:{}/run_cmd'.format(host, port)
    log.info('Sending {} data: {}'.format(proxy_uri, cmd))
    response = requests.post(proxy_uri, data=cmd, timeout=5).json()
    log.info('Requests Response: {}'.format(repr(response)))
    if response['status'] != 0:
        return None
    return json.loads(response['output'])


def vip_app(container: marathon.Container, network: marathon.Network, host: str, vip: str):
    # user_net_port is only actually used for USER network because this cannot be assigned
    # by marathon
    if network in [marathon.Network.HOST, marathon.Network.BRIDGE]:
        # both of these cases will rely on marathon to assign ports
        return test_helpers.marathon_test_app(
            network=network,
            host_constraint=host,
            vip=vip,
            container_type=container,
            healthcheck_protocol=marathon.Healthcheck.MESOS_HTTP)
    elif network == marathon.Network.USER:
        return test_helpers.marathon_test_app(
            network=network,
            host_port=unused_port(marathon.Network.USER),
            host_constraint=host,
            vip=vip,
            container_type=container,
            healthcheck_protocol=marathon.Healthcheck.MESOS_HTTP)
    else:
        raise AssertionError('Unexpected network: {}'.format(network.value))


def generate_vip_app_permutations():
    """ Generate all possible network interface permutations for applying vips
    """
    return [(container, vip_net, proxy_net)
            for container in [marathon.Container.NONE, marathon.Container.MESOS, marathon.Container.DOCKER]
            for vip_net in [marathon.Network.USER, marathon.Network.BRIDGE, marathon.Network.HOST]
            for proxy_net in [marathon.Network.USER]
            # only DOCKER containers support BRIDGE network
            if marathon.Network.BRIDGE not in (vip_net, proxy_net) or container == marathon.Container.DOCKER]


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_0(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_1(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_2(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_3(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_4(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_5(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_6(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_7(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_8(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


@pytest.mark.slow
@pytest.mark.skipif(
    not lb_enabled(),
    reason='Load Balancer disabled')
@pytest.mark.parametrize(
    'container,vip_net,proxy_net',
    generate_vip_app_permutations())
def test_vip_9(dcos_api_session,
               container: marathon.Container,
               vip_net: marathon.Network,
               proxy_net: marathon.Network):
    return gen_test_vip(dcos_api_session, container, vip_net, proxy_net)


def gen_test_vip(dcos_api_session,
                 container: marathon.Container,
                 vip_net: marathon.Network,
                 proxy_net: marathon.Network):
    '''Test VIPs between the following source and destination configurations:
        * containers: DOCKER, UCR and NONE
        * networks: USER, BRIDGE (docker only), HOST
        * agents: source and destnations on same agent or different agents
        * vips: named and unnamed vip

    Origin app will be deployed to the cluster with a VIP. Proxy app will be
    deployed either to the same host or elsewhere. Finally, a thread will be
    started on localhost (which should be a master) to submit a command to the
    proxy container that will ping the origin container VIP and then assert
    that the expected origin app UUID was returned
    '''
    errors = 0
    tests = setup_vip_workload_tests(dcos_api_session, container, vip_net, proxy_net)
    for vip, hosts, cmd, origin_app, proxy_app in tests:
        log.info("Testing :: VIP: {}, Hosts: {}".format(vip, hosts))
        log.info("Remote command: {}".format(cmd))
        proxy_info = dcos_api_session.marathon.get('v2/apps/{}'.format(proxy_app['id'])).json()
        proxy_task_info = proxy_info['app']['tasks'][0]
        if proxy_net == marathon.Network.USER:
            proxy_host = proxy_task_info['ipAddresses'][0]['ipAddress']
            if container == marathon.Container.DOCKER:
                proxy_port = proxy_task_info['ports'][0]
            else:
                proxy_port = proxy_app['ipAddress']['discovery']['ports'][0]['number']
        else:
            proxy_host = proxy_task_info['host']
            proxy_port = proxy_task_info['ports'][0]
        try:
            ensure_routable(cmd, proxy_host, proxy_port)['test_uuid'] == origin_app['env']['DCOS_TEST_UUID']

            log.info('Purging application: {}'.format(origin_app['id']))
            dcos_api_session.marathon.delete('v2/apps/{}'.format(origin_app['id'])).raise_for_status()
            log.info('Purging application: {}'.format(proxy_app['id']))
            dcos_api_session.marathon.delete('v2/apps/{}'.format(proxy_app['id'])).raise_for_status()
        except Exception as e:
            log.error('Exception: {}'.format(e))

            ip = check_output(['/opt/mesosphere/bin/detect_ip']).decode().strip()
            state = requests.get('http://{}:5050/state'.format(ip)).text
            log.info("MESOS STATE: {}".format(state))

            errors = errors + 1
        finally:
            pass
    assert errors == 0


def setup_vip_workload_tests(dcos_api_session, container, vip_net, proxy_net):
    same_hosts = [True, False] if len(dcos_api_session.all_slaves) > 1 else [True]
    tests = [vip_workload_test(dcos_api_session, container, vip_net, proxy_net, named_vip, same_host)
             for named_vip in [True, False]
             for same_host in same_hosts]
    for vip, hosts, cmd, origin_app, proxy_app in tests:
        # We do not need the service endpoints because we have deterministically assigned them
        log.info('Starting apps :: VIP: {}, Hosts: {}'.format(vip, hosts))
        log.info("Origin app: {}".format(origin_app))
        dcos_api_session.marathon.post('v2/apps', json=origin_app).raise_for_status()
        log.info("Proxy app: {}".format(proxy_app))
        dcos_api_session.marathon.post('v2/apps', json=proxy_app).raise_for_status()
    for vip, hosts, cmd, origin_app, proxy_app in tests:
        log.info("Deploying apps :: VIP: {}, Hosts: {}".format(vip, hosts))
        log.info('Deploying origin app: {}'.format(origin_app['id']))
        wait_for_tasks_healthy(dcos_api_session, origin_app)
        log.info('Deploying proxy app: {}'.format(proxy_app['id']))
        wait_for_tasks_healthy(dcos_api_session, proxy_app)
        log.info('Apps are ready')
    return tests


def vip_workload_test(dcos_api_session, container, vip_net, proxy_net, named_vip, same_host):
    origin_host = dcos_api_session.all_slaves[0]
    proxy_host = dcos_api_session.all_slaves[0] if same_host else dcos_api_session.all_slaves[1]
    if named_vip:
        vip_port = unused_port('namedvip')
        vip = '/namedvip:{}'.format(vip_port)
        vipaddr = 'namedvip.marathon.l4lb.thisdcos.directory:{}'.format(vip_port)
    else:
        vip_port = unused_port('1.1.1.7')
        vip = '1.1.1.7:{}'.format(vip_port)
        vipaddr = vip
    cmd = '/opt/mesosphere/bin/curl -s -f -m 5 http://{}/test_uuid'.format(vipaddr)
    origin_app, origin_app_uuid = vip_app(container, vip_net, origin_host, vip)
    proxy_app, proxy_app_uuid = vip_app(container, proxy_net, proxy_host, None)
    # allow these apps to run on public slaves
    origin_app['acceptedResourceRoles'] = ['*', 'slave_public']
    proxy_app['acceptedResourceRoles'] = ['*', 'slave_public']
    hosts = list(set([origin_host, proxy_host]))
    return (vip, hosts, cmd, origin_app, proxy_app)


@retrying.retry(
    wait_fixed=5000,
    stop_max_delay=20 * 60 * 1000,
    retry_on_result=lambda res: res is False)
def wait_for_tasks_healthy(dcos_api_session, app_definition):
    info = dcos_api_session.marathon.get('v2/apps/{}'.format(app_definition['id'])).json()
    return info['app']['tasksHealthy'] == app_definition['instances']


@retrying.retry(wait_fixed=2000,
                stop_max_delay=100 * 2000,
                retry_on_exception=lambda x: True)
def geturl(url):
    rs = requests.get(url)
    assert rs.status_code == 200
    r = rs.json()
    log.info('geturl {} -> {}'.format(url, r))
    return r
