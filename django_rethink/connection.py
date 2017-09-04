# Copyright 2017 Klarna AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import rethinkdb as r
from django.conf import settings

class RethinkConnectionReconnector(object):
    def __init__(self, connection):
        self.connection = connection
    def _start(self, *args, **kwargs):
        if not self.connection.is_open():
            self.connection.reconnect(False)
        return self.connection._start(*args, **kwargs)
    def __getattr__(self, value):
        return getattr(self.connection, value)

try:
    import gevent.local
    connection = gevent.local.local()
except ImportError:
    import threading
    connection = threading.local()

def get_connection():
    if not hasattr(connection, 'conn'):
        connection.conn = RethinkConnectionReconnector(
            r.connect(
                host=settings.RETHINK_DB_HOST,
                port=settings.RETHINK_DB_PORT,
                db=settings.RETHINK_DB_DB))
    return connection.conn
