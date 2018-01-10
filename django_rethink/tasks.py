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
from django_rethink.serializers import RethinkSerializer, RethinkObjectNotFound

logger = logging.getLogger("django_rethink.tasks")

def _distributed_lock_id(name):
    return name

@shared_task(bind=True)
def rethinkdb_lock(self, name, token=None, timeout=300):
    if token is None:
        token = self.request.root_id
    result = r.table("locks").insert({
        "id": _distributed_lock_id(name),
        "token": token,
        "server": socket.gethostname(),
        "timestamp": r.now(),
    }).run(get_connection())
    if result['inserted'] == 0:
        self.retry(exc=Exception("failed to acquire lock %s" % name),
                   countdown=1, max_retries=timeout)
    else:
        logger.info("locked %s with token %s", name, token)
        return token

@shared_task(bind=True)
def rethinkdb_unlock(self, *args, **kwargs):
    if 'name' in kwargs:
        name = kwargs['name']
    else:
        name = args[0]
        args = args[1:]
    token = kwargs.get('token', self.request.root_id)
    result = r.table("locks").get_all(_distributed_lock_id(name)). \
        filter({"token": token}).delete().run(get_connection())
    if result['deleted'] == 1:
        logger.info("unlocked %s", name)
    else:
        logger.warning("unable to unlock %s, token was not %s", name, token)
    if len(args) > 0:
        return args[0]

def all_subclasses(cls):
    return cls.__subclasses__() + [g for s in cls.__subclasses__() for g in all_subclasses(s)]

@shared_task
def review_execute(review):
    for cls in all_subclasses(RethinkSerializer):
        if cls.Meta.table_name == review['object_type']:
            break
    else:
        raise Exception("unable to find class for object type %s" % review['object_type'])
    try:
        obj = cls.get(id=review['object_id'])
    except RethinkObjectNotFound:
        obj = None
    serializer = cls(obj,
        data=review['object'],
        partial=review['is_partial'],
        context={'username': review['submitter'], 'reviewed': True}
    )
    if review.get('is_delete', False):
        return serializer.delete()
    else:
        serializer.is_valid(raise_exception=True)
        return serializer.save()
