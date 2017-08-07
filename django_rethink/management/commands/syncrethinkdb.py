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

from django.core.management.base import BaseCommand, CommandError
import rethinkdb as r
from importlib import import_module
from django_rethink.tasks import all_subclasses

class Command(BaseCommand):
    help = 'Creates a database in the Rethink database configured.'
    can_import_settings = True

    def handle(self, *args, **kwargs):
        from django.conf import settings
        from django.apps import apps
        from django_rethink import RethinkSerializer

        for app in apps.get_app_configs():
            try:
                import_module(app.name + ".serializers")
            except ImportError:
                pass

        conn = r.connect(host=settings.RETHINK_DB_HOST, port=settings.RETHINK_DB_PORT)
        if settings.RETHINK_DB_DB not in r.db_list().run(conn):
            r.db_create(settings.RETHINK_DB_DB).run(conn)

        classes = filter(lambda x: not x.Meta.abstract, all_subclasses(RethinkSerializer))
        tables_now = set(r.db(settings.RETHINK_DB_DB).table_list().run(conn))
        replicas = r.db("rethinkdb").table("server_config").count().run(conn)

        for cls in classes:
            if cls.Meta.table_name not in tables_now:
                r.db(settings.RETHINK_DB_DB).table_create(cls.Meta.table_name).run(conn)
            indices_now = set(r.db(settings.RETHINK_DB_DB).table(cls.Meta.table_name).index_list().run(conn))
            for index in cls.Meta.indices:
                if isinstance(index, tuple):
                    if index[0] in indices_now:
                        continue
                    if isinstance(index[-1], dict):
                        kwargs = index[-1]
                        index = index[:-1]
                    else:
                        kwargs = {}
                    r.db(settings.RETHINK_DB_DB).table(cls.Meta.table_name).index_create(*index, **kwargs).run(conn)
                else:
                    if index in indices_now:
                        continue
                    r.db(settings.RETHINK_DB_DB).table(cls.Meta.table_name).index_create(index).run(conn)

            r.db(settings.RETHINK_DB_DB).table(cls.Meta.table_name).index_wait().run(conn)
            r.db(settings.RETHINK_DB_DB).table(cls.Meta.table_name).reconfigure(shards=1, replicas=replicas).run(conn)
