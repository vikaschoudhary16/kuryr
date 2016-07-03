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

from neutronclient.neutron import client
from oslo_config import cfg
from oslo_log import log

#from kuryr import app
from kuryr import utils

LOG = log.getLogger(__name__)


def _get_cloud_config(cloud='devstack-admin'):
    return os_client_config.OpenStackConfig().get_one_cloud(cloud=cloud)


def _credentials(cloud='devstack-admin'):
    """Retrieves credentials to run functional tests

    Credentials are either read via os-client-config from the environment
    or from a config file ('clouds.yaml'). Environment variables override
    those from the config file.

    devstack produces a clouds.yaml with two named clouds - one named
    'devstack' which has user privs and one named 'devstack-admin' which
    has admin privs. This function will default to getting the devstack-admin
    cloud as that is the current expected behavior.
    """
    return _get_cloud_config(cloud=cloud).get_auth_args()


def _get_neutron_client_from_creds():
    creds = _credentials()
    username = creds['username']
    tenant_name = creds['project_name']
    password = creds['password']
    auth_url = creds['auth_url'] + "/v2.0"
    neutron_client = client.Client('2.0', username=username,
                                   tenant_name=tenant_name,
                                   password=password,
                                   auth_url=auth_url)
    return neutron_client


def get_neutron_client():
    """Creates the Neutron client for communicating with Neutron."""
    try:
        # First try to retrieve neutron client from a working OS deployment
        # This is used for gate testing.
        # Since this always use admin credentials, next patch will introduce
        # a config parameter that disable this for production environments
        neutron_client = _get_neutron_client_from_creds()
        return neutron_client
    except Exception:
            pass
    cfg.CONF.import_group('neutron_client', 'kuryr.lib.config')
    cfg.CONF.import_group('keystone_client', 'kuryr.lib.config')

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

"""
def neutron_client():
    if not hasattr(app, 'neutron'):
        app.neutron = get_neutron_client()
        app.enable_dhcp = cfg.CONF.neutron_client.enable_dhcp
        app.vif_plug_is_fatal = cfg.CONF.neutron_client.vif_plugging_is_fatal
        app.vif_plug_timeout = cfg.CONF.neutron_client.vif_plugging_timeout
        app.neutron.format = 'json'
"""


class Handler(object):

    def __init__(self):
        super(Handler, self).__init__()

    # Extension
    def show_extension(self, ctxt, **attrs):
        LOG.debug("ext %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.show_extension(attrs.get('ext', ''))

    # subnetpool
    def create_subnetpool(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.create_subnetpool(**attrs)

    def delete_subnetpool(self, ctxt, subnetpool):
        LOG.debug("pool %s ", subnetpool)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.delete_subnetpool(subnetpool)

    def list_subnetpools(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = get_neutron_client()
        return nc.list_subnetpools(**attrs)

    # network
    def create_network(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.create_network(**attrs)

    def update_network(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.update_network(**attrs)

    def delete_network(self, ctxt, net):
        LOG.debug("net %s ", net)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.delete_network(net)

    def list_networks(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.list_networks(**attrs)

    # subnet
    def create_subnet(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()

        return nc.create_subnet(**attrs)

    def update_subnet(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.update_subnet(**attrs)

    def delete_subnet(self, ctxt, subnet):
        LOG.debug("subnet %s ", subnet)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.delete_subnet(subnet)

    def list_subnets(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.list_subnets(**attrs)

    # port
    def create_port(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.create_port(**attrs)

    def update_port(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.update_port(**attrs)

    def delete_port(self, ctxt, port):
        LOG.debug("port %s ", port)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()

        return nc.delete_port(port)

    def list_ports(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.list_ports(**attrs)

    # tags
    def add_tag(self, ctxt, _type, _id, tag):
        LOG.debug("id %s ", _id)
        LOG.debug("tag %s ", tag)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.add_tag(_type, _id, tag)

    def remove_tag(self, ctxt, _type, _id, tag):
        LOG.debug("id %s ", _id)
        LOG.debug("tag %s ", tag)

        # TODO(vikasc): use ctxt
        nc = get_neutron_client()
        return nc.remove_tag(_type, _id, tag)
