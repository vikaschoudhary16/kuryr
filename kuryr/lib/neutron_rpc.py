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

from kuryr.lib import context
from kuryr.lib import rpc_service

LOG = log.getLogger(__name__)

# The Backend API class serves as a AMQP client for communicating
# on a topic exchange specific to the controller.  This allows the
# API to trigger operations on the controller


class RPCDriver(rpc_service.API):

    def __init__(self, cfg):
        # TODO(vikasc): Read credentials from config file
        ctxt = context.make_context(
            auth_url='http://127.0.0.1:35357/v2.0',
            user_name='admin',
            project_name='admin',
            password='pass'
        )
        transport = None

        super(RPCDriver, self).__init__(transport, ctxt,
                                        topic='kuryr-controller')

    # subnetpool
    def create_subnetpool(self, **attrs):
        return self._call('create_subnetpool', **attrs)

    def delete_subnetpool(self, **attrs):
        return self._call('delete_subnetpool', **attrs)

    def list_subnetpools_by_name(self, **attrs):
        return self._call('list_subnetpools_by_name', **attrs)

    def list_subnetpools_by_id(self, **attrs):
        return self._call('list_subnetpools_by_id', **attrs)

    def show_extension(self, **attrs):
        return self._call('show_extension', **attrs)

    # network
    def create_network(self, **attrs):
        return self._call('create_network', **attrs)

    def update_network(self, **attrs):
        return self._call('update_network', **attrs)

    def delete_network(self, **attrs):
        return self._call('delete_network', **attrs)

    def list_networks(self, **attrs):
        return self._call('list_networks', **attrs)

    def create_subnet(self, **attrs):
        return self._call('create_subnet', **attrs)

    def delete_subnet(self, **attrs):
        return self._call('delete_subnet', **attrs)

    def list_subnets(self, **attrs):
        return self._call('list_subnets', **attrs)

    def create_port(self, **attrs):
        return self._call('create_port', **attrs)

    def delete_port(self, **attrs):
        return self._call('delete_port', **attrs)

    def update_port(self, **attrs):
        return self._call('update_port', **attrs)

    def show_port(self, **attrs):
        return self._call('show_port', **attrs)

    def list_ports(self, **attrs):
        return self._call('list_ports', **attrs)

    def add_tag(self, **attrs):
        return self._call('add_tag', **attrs)

    def remove_tag(self, **attrs):
        LOG.debug("tag details %s ", attrs)

        return self._call('remove_tag', **attrs)

    # security_groups
    def create_security_group(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self._call('create_security_group', **attrs)

    def delete_security_group(self, **attrs):
        LOG.debug("sg %s ", attrs)

        return self._call('delete_security_group', **attrs)

    def list_security_groups(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self._call('list_security_groups', **attrs)

    # security_group_rule
    def create_security_group_rule(self, **attrs):
        LOG.debug("attrs %s ", attrs)

        return self.neutron._call('create_security_group_rule', **attrs)
