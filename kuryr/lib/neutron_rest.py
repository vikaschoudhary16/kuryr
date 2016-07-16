# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os_client_config


from neutronclient.common import exceptions as n_exceptions
from neutronclient.neutron import client
from oslo_log import log

from kuryr import utils

LOG = log.getLogger(__name__)


class RestDriver(object):

    def __init__(self, cfg=None, ctxt=None):
        if cfg:
            self.neutron = self._get_neutron_client(cfg)
        if ctxt:
            self.neutron = self._get_neutron_client_ctxt(ctxt)
        self.neutron.format = 'json'

    def show_extension(self, **attrs):
        try:
            self.neutron.show_extension(attrs.get('ext', ''))
        except n_exceptions.NeutronClientException as e:
            raise e

        # subnetpool
    def create_subnetpool(self, **attrs):
        LOG.debug("attrs %s ", attrs)
        return self.neutron.create_subnetpool(attrs)

    def delete_subnetpool(self, **attrs):
        LOG.debug("pool %s ", attrs)
        return self.neutron.delete_subnetpool(attrs.get('pool_id', ''))

    def list_subnetpools_by_name(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_subnetpools(name=attrs.get('name', ''))

    def list_subnetpools_by_id(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_subnetpools(id=attrs.get('id', ''))

    # network
    def create_network(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.create_network(attrs)

    def update_network(self, **attrs):
        LOG.debug("attrs %s ", attrs)
        netid = attrs.get('uuid', '')
        net = attrs.get('net', '')
        return self.neutron.update_network(netid, net)

    def delete_network(self, **attrs):
        LOG.debug("net %s ", attrs)
        netid = attrs.get('netid', '')
        return self.neutron.delete_network(netid)

    def list_networks(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_networks(**attrs)

    # subnet
    def create_subnet(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.create_subnet(attrs)

    def update_subnet(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.update_subnet(attrs)

    def delete_subnet(self, **attrs):
        LOG.debug("subnet %s ", attrs)

        subnet_id = attrs.get('subnet_id', '')

        return self.neutron.delete_subnet(subnet_id)

    def list_subnets(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_subnets(**attrs)

    # port
    def create_port(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.create_port(attrs)

    def show_port(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.show_port(attrs.get('port_id', ''))

    def update_port(self, **attrs):
        LOG.debug("attrs %s ", attrs)
        port_id = attrs.get('id', '')
        port = attrs.get('port', '')

        return self.neutron.update_port(port_id, port)

    def delete_port(self, **attrs):
        LOG.debug("port %s ", attrs)

        return self.neutron.delete_port(attrs.get('portid', ''))

    def list_ports(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_ports(**attrs)

    # tags
    def add_tag(self, **attrs):
        LOG.debug("tag details %s ", attrs)
        _type = attrs.get('resource', '')
        _id = attrs.get('netid', '')
        tag = attrs.get('tag', '')

        return self.neutron.add_tag(_type, _id, tag)

    def remove_tag(self, **attrs):
        LOG.debug("tag details %s ", attrs)
        _type = attrs.get('resource', '')
        _id = attrs.get('netid', '')
        tag = attrs.get('tag', '')

        return self.neutron.remove_tag(_type, _id, tag)

    # security_groups
    def create_security_group(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.create_security_group(attrs)

    def delete_security_group(self, **attrs):
        LOG.debug("sg %s ", attrs)

        return self.neutron.delete_security_group(attrs.get('id', ''))

    def list_security_groups(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.list_security_groups(**attrs)

    # security_group_rule
    def create_security_group_rule(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron.create_security_group_rule(attrs)

    def _get_cloud_config(self, cloud='devstack-admin'):
        return os_client_config.OpenStackConfig().get_one_cloud(cloud=cloud)

    def _credentials(self, cloud='devstack-admin'):
        """Retrieves credentials to run functional tests

        Credentials are either read via os-client-config from the environment
        or from a config file ('clouds.yaml'). Environment variables override
        those from the config file.

        devstack produces a clouds.yaml with two named clouds - one named
        'devstack' which has user privs and one named 'devstack-admin' which
        has admin privs. This function will default to getting the
        devstack-admin cloud as that is the current expected behavior.
        """
        return self._get_cloud_config(cloud=cloud).get_auth_args()

    def _get_neutron_client_from_creds(self):
        creds = self._credentials()
        username = creds['username']
        tenant_name = creds['project_name']
        password = creds['password']
        auth_url = creds['auth_url'] + "/v2.0"
        neutron_client = client.Client('2.0', username=username,
                                       tenant_name=tenant_name,
                                       password=password,
                                       auth_url=auth_url)
        return neutron_client

    def _get_neutron_client(self, cfg):
        """Create the Neutron client for communicating with Neutron."""
        try:
            # First try to retrieve neutron client from a working OS deployment
            # This is used for gate testing.
            # Since this always use admin credentials, next patch will
            # introduce a config parameter that disable this for production
            # environments
            neutron_client = self._get_neutron_client_from_creds()
            return neutron_client
        except Exception:
            pass

        keystone_conf = cfg.CONF.keystone_client
        username = keystone_conf.admin_user
        tenant_name = keystone_conf.admin_tenant_name
        password = keystone_conf.admin_password
        auth_token = keystone_conf.admin_token
        auth_uri = keystone_conf.auth_uri.rstrip('/')
        ca_cert = keystone_conf.auth_ca_cert
        insecure = keystone_conf.auth_insecure

        neutron_uri = cfg.CONF.neutron_client.neutron_uri
        if username and password:
            # Authenticate with password crentials
            neutron_client = utils.get_neutron_client(
                url=neutron_uri, username=username, tenant_name=tenant_name,
                password=password, auth_url=auth_uri,
                ca_cert=ca_cert, insecure=insecure)
        else:
            neutron_client = utils.get_neutron_client_simple(
                url=neutron_uri, auth_url=auth_uri, token=auth_token)
        return neutron_client

    def _get_neutron_client_ctxt(self, ctxt):
        # TODO(vikasc): use ctxt to get neutron client
        neutron_uri = 'http://127.0.0.1:9696'
        username = 'admin'
        tenant_name = 'admin'
        password = 'pass'
        auth_uri = 'http://127.0.0.1:35357/v2.0'
        neutron_client = utils.get_neutron_client(
            url=neutron_uri, username=username, tenant_name=tenant_name,
            password=password, auth_url=auth_uri)
        return neutron_client
