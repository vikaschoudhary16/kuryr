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

import sys

from oslo_log import log
from oslo_service import service

from kuryr import controllers
from kuryr.lib import config
from kuryr.lib import rpc_service
from kuryr.lib import short_id

LOG = log.getLogger(__name__)

config.init(sys.argv[1:])

log.setup(config.CONF, 'Kuryr')


def start():
    controller_id = short_id.generate_id()
    endpoints = [controllers.Handler()]
    server = rpc_service.Service.create('kuryr-controller',
                                        controller_id, endpoints,
                                        binary='kuryr-controller')
    launcher = service.launch(config.CONF, server)
    LOG.debug("LAUNCHED")
    launcher.wait()


if __name__ == '__main__':
    start()
