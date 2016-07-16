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


from oslo_log import log

from kuryr.lib import neutron_rest

LOG = log.getLogger(__name__)


class Handler(object):

    def __init__(self):
        pass

    # Extension
    def show_extension(self, ctxt, **attrs):
        LOG.debug("ext %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.show_extension(attrs)

    # subnetpool
    def create_subnetpool(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.create_subnetpool(attrs)

    def delete_subnetpool(self, ctxt, **attrs):
        LOG.debug("pool %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.delete_subnetpool(attrs)

    def list_subnetpools_by_name(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)

        return nc.list_subnetpools(attrs)

    def list_subnetpools_by_id(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)

        return nc.list_subnetpools(attrs)

    # network
    def create_network(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.create_network(attrs)

    def update_network(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.update_network(attrs)

    def delete_network(self, ctxt, **attrs):
        LOG.debug("net %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.delete_network(attrs)

    def list_networks(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.list_networks(attrs)

    # subnet
    def create_subnet(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)

        return nc.create_subnet(attrs)

    def update_subnet(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.update_subnet(attrs)

    def delete_subnet(self, ctxt, **attrs):
        LOG.debug("subnet %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.delete_subnet(attrs)

    def list_subnets(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.list_subnets(attrs)

    # port
    def create_port(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.create_port(attrs)

    def show_port(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.show_port(attrs)

    def update_port(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)
        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.update_port(attrs)

    def delete_port(self, ctxt, **attrs):
        LOG.debug("port %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)

        return nc.delete_port(attrs)

    def list_ports(self, ctxt, **attrs):
        LOG.debug("attrs %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.list_ports(attrs)

    # tags
    def add_tag(self, ctxt, **attrs):
        LOG.debug("tag details %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.add_tag(attrs)

    def remove_tag(self, ctxt, **attrs):
        LOG.debug("tag details %s ", attrs)

        nc = neutron_rest.RestDriver(ctxt=ctxt)
        return nc.remove_tag(attrs)
