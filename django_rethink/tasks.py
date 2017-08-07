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

from __future__ import absolute_import

import time
import socket
import logging
import rethinkdb as r
from celery import shared_task
from django_rethink.connection import get_connection
from django_rethink.serializers import RethinkSerializer

logger = logging.getLogger("django_rethink.tasks")

def _distributed_lock_id(name):
    return name

@shared_task(bind=True)
def rethinkdb_lock(self, name, interval=1):
    result = {'inserted': 0}
    while result['inserted'] == 0:
        result = r.table("locks").insert({
            "id": _distributed_lock_id(name),
            "token": self.request.root_id,
            "server": socket.gethostname(),
            "timestamp": r.now(),
        }).run(get_connection())
        time.sleep(interval)
    logger.info("locked %s with token %s", name, self.request.root_id)

@shared_task(bind=True)
def rethinkdb_unlock(self, name, token=None):
    if token is None:
        token = self.request.root_id
    result = r.table("locks").get_all(_distributed_lock_id(name)). \
        filter({"token": token}).delete().run(get_connection())
    if result['deleted'] == 1:
        logger.info("unlocked %s", name)
    else:
        logger.warning("unable to unlock %s, token was not %s", name, token)

def all_subclasses(cls):
    return cls.__subclasses__() + [g for s in cls.__subclasses__() for g in all_subclasses(s)]

@shared_task
def review_execute(review):
    for cls in all_subclasses(RethinkSerializer):
        if cls.Meta.table_name == review['object_type']:
            break
    else:
        raise Exception("unable to find class for object type %s" % review['object_type'])
    serializer = cls(cls.get(id=review['object_id']),
        data=review['object'],
        partial=review['is_partial'],
        context={'username': review['submitter'], 'reviewed': True}
    )
    serializer.is_valid(raise_exception=True)
    return serializer.save()
