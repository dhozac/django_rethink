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

from django.views.generic.base import ContextMixin, View
from django.views.generic.list import MultipleObjectMixin
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.encoding import force_text
from rest_framework import serializers
import json
import six
import rethinkdb as r
import time

class BadRequestException(Exception):
    pass

class RethinkConnectionReconnector(object):
    def __init__(self, host, port, db):
        self.connection = r.connect(host=host, port=port, db=db)
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
        connection.conn = RethinkConnectionReconnector(host=settings.RETHINK_DB_HOST, port=settings.RETHINK_DB_PORT, db=settings.RETHINK_DB_DB)
    return connection.conn

class RethinkMixin(object):
    rethink_conn = None
    def get_connection(self):
        if self.rethink_conn is None:
            self.rethink_conn = get_connection()
        return self.rethink_conn

class RethinkSingleObjectMixin(ContextMixin, RethinkMixin):
    pk_url_kwarg = "id"
    slug_url_kwarg = "slug"
    pk_field = "id"
    slug_field = "slug"
    table_name = None
    queryset = None
    pk_index_name = None
    slug_index_name = None

    def get_object_qs(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()

        pk = self.kwargs.get(self.pk_url_kwarg, None)
        slug = self.kwargs.get(self.slug_url_kwarg, None)
        if pk is None and slug is None:
            raise AttributeError("Generic detail view %s must be called with "
                                 "either an object pk or a slug."
                                 % self.__class__.__name__)
        elif pk is not None:
            if self.pk_index_name:
                queryset = queryset.get_all(pk, index=self.pk_index_name)
            else:
                queryset = queryset.filter(r.row[self.pk_field] == pk)
        elif pk is None and slug is not None:
            if self.slug_index_name:
                queryset = queryset.get_all(slug, index=self.slug_index_name)
            else:
                queryset = queryset.filter(r.row[self.slug_field] == slug)
        return queryset

    def get_object(self, queryset=None):
        queryset = self.get_object_qs(queryset)

        try:
            obj = queryset.run(self.get_connection()).next()
        except r.net.DefaultCursorEmpty:
            raise Http404(_("No %(verbose_name)s found matching the query") %
                          {'verbose_name': self.table_name})

        return obj

    def get_queryset(self):
        if self.queryset is None:
            if self.table_name:
                return r.table(self.table_name)
            else:
                raise ImproperlyConfigured(
                    "%(cls)s is missing a QuerySet. Define "
                    "%(cls)s.model, %(cls)s.queryset, or override "
                    "%(cls)s.get_queryset()." % {
                        'cls': self.__class__.__name__
                    }
                )
        return self.queryset


    def get_context_data(self, **kwargs):
        """
        Insert the single object into the context dict.
        """
        context = {}
        if self.object:
            context['object'] = self.object
            context_object_name = self.get_context_object_name(self.object)
            if context_object_name:
                context[context_object_name] = self.object
        context.update(kwargs)
        return super(RethinkSingleObjectMixin, self).get_context_data(**context)

class RethinkUpdateView(RethinkSingleObjectMixin, View):
    insert_if_missing = False
    success_url = None

    def get_success_url(self):
        if self.success_url:
            return self.success_url.format(**self.object)
        else:
            raise ImproperlyConfigured(
                "No URL to redirect to. Provide a success_url.")

    def get_update_data(self):
        return self.get_request_data()

    def get_request_data(self):
        if self.request.META['CONTENT_TYPE'] == "application/json":
            return json.loads(force_text(self.request.body))
        else:
            return dict(self.request.POST)

    def post_update(self):
        pass

    def post(self, *args, **kwargs):
        conn = self.get_connection()
        update_data = self.get_update_data()
        result = self.get_object_qs().update(r.expr(update_data, nesting_depth=40)).run(conn)
        if max(result.values()) == 0:
            result = r.table(self.table_name).insert(r.expr(self.get_insert_data(update_data), nesting_depth=40)).run(conn)
        self.post_update()
        if self.request.META['CONTENT_TYPE'] == "application/json":
            return HttpResponse(json.dumps({'success': True}), content_type="application/json")
        else:
            return HttpResponseRedirect(self.get_success_url())

    def put(self, *args, **kwargs):
        return self.post(*args, **kwargs)

    @csrf_exempt
    def dispatch(self, *args, **kwargs):
        return super(RethinkUpdateView, self).dispatch(*args, **kwargs)

class RethinkAPIMixin(object):
    rethink_conn = None
    pk_url_kwarg = "id"
    slug_url_kwarg = "slug"
    queryset = None
    pk_index_name = None
    slug_index_name = None
    group_filter_fields = None
    group_filter_extras = []

    def get_connection(self):
        if self.rethink_conn is None:
            self.rethink_conn = get_connection()
        return self.rethink_conn

    def get_slug(self):
        return self.kwargs.get(self.slug_url_kwarg, None)

    def get_object_qs(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()

        pk = self.kwargs.get(self.pk_url_kwarg, None)
        slug = self.get_slug()
        if pk is None and slug is None:
            raise AttributeError("Generic detail view %s must be called with "
                                 "either an object pk or a slug."
                                 % self.__class__.__name__)
        elif pk is not None:
            if self.pk_index_name:
                queryset = queryset.get_all(pk, index=self.pk_index_name)
            else:
                queryset = queryset.filter(r.row[self.serializer_class.Meta.pk_field] == pk)
        elif pk is None and slug is not None:
            if self.serializer_class.Meta.slug_field in map(lambda x: x if not isinstance(x, tuple) else x[0], self.serializer_class.Meta.indices):
                queryset = queryset.get_all(slug, index=self.serializer_class.Meta.slug_field)
            else:
                queryset = queryset.filter(r.row[self.serializer_class.Meta.slug_field] == slug)
        return queryset

    def get_queryset(self):
        if self.queryset is None:
            if self.serializer_class.Meta.table_name:
                queryset = r.table(self.serializer_class.Meta.table_name)
            else:
                raise ImproperlyConfigured(
                    "%(cls)s is missing a QuerySet. Define "
                    "%(cls)s.model, %(cls)s.queryset, or override "
                    "%(cls)s.get_queryset()." % {
                        'cls': self.__class__.__name__
                    }
                )
        else:
            queryset = self.queryset

        return queryset

    def default_filter_queryset(self, queryset):
        return queryset

    def _filter_queryset(self, queryset):
        if self.group_filter_fields is not None and not self.request.user.is_superuser and (not self.request.user.is_global_readonly or self.request.method not in ('GET',)):
            groups = self.request.user.groups.all().values_list('name', flat=True)
            if self.group_filter_extras:
                groups = list(groups) + self.group_filter_extras
            if len(groups) == 0:
                return queryset.filter(lambda obj: False)
            group_filters = [queryset.get_all(*groups, index=group_filter_field) for group_filter_field in self.group_filter_fields]
            queryset = reduce(lambda x, y: x.union(y), group_filters)
            queryset = queryset.distinct()

        pk = self.kwargs.get(self.pk_url_kwarg, None)
        slug = self.get_slug()
        if pk is not None:
            queryset = queryset.filter(r.row[self.serializer_class.Meta.pk_field] == pk)
        elif slug is not None:
            queryset = queryset.filter(r.row[self.serializer_class.Meta.slug_field] == slug)

        queryset = self.default_filter_queryset(queryset)

        if self.request.query_params:
            fields = self.serializer_class.__dict__['_declared_fields'].keys()
            for key, val in self.request.query_params.iterlists():
                regexp = None
                if '__' in key:
                    keys = key.split("__")
                    key = keys[0]
                    if keys[-1] == 'regexp':
                        regexp = keys.pop()
                else:
                    keys = [key]
                def get_keys(obj, keys):
                    for key in keys:
                        obj = obj[key]
                    return obj
                def get_dict_keys(keys):
                    ret = {}
                    d = ret
                    for key in keys[:-1]:
                        d[key] = {}
                        d = d[key]
                    d[keys[-1]] = True
                    return ret
                if val == ['']:
                    queryset = queryset.filter(lambda obj: (obj.has_fields(get_dict_keys(keys)).not_() | r.expr(['', None]).contains(get_keys(obj, keys))))
                elif key in fields and isinstance(self.serializer_class.__dict__['_declared_fields'][key], serializers.ListField):
                    queryset = queryset.filter(lambda obj: r.expr(val).set_intersection(get_keys(obj, keys)).count() > 0)
                elif key in fields and isinstance(self.serializer_class.__dict__['_declared_fields'][key], serializers.IntegerField):
                    queryset = queryset.filter(lambda obj: r.expr(map(int, val)).contains(get_keys(obj, keys)))
                elif key in fields and isinstance(self.serializer_class.__dict__['_declared_fields'][key], serializers.BooleanField):
                    queryset = queryset.filter(lambda obj: r.expr(map(json.loads, val)).contains(get_keys(obj, keys)))
                elif key in fields and regexp is not None:
                    queryset = queryset.filter(lambda obj: get_keys(obj, keys).match(val[0]))
                elif key in fields:
                    queryset = queryset.filter(lambda obj: r.expr(val).contains(get_keys(obj, keys)))

        if self.serializer_class.Meta.order_by:
            queryset = queryset.order_by(*self.serializer_class.Meta.order_by)

        return queryset

    def filter_queryset(self, queryset):
        queryset = self._filter_queryset(queryset)
        return list(queryset.run(self.get_connection()))

    def get_object(self):
        queryset = self.get_object_qs(self.get_queryset())

        try:
            obj = queryset.run(self.get_connection()).next()
        except r.net.DefaultCursorEmpty:
            raise Http404(_("No %(verbose_name)s found matching the query") %
                          {'verbose_name': self.serializer_class.Meta.table_name})

        self.check_object_permissions(self.request, obj)

        return obj

    def perform_destroy(self, instance):
        self.get_serializer(instance).delete()

def validate_unique_key(self, field):
    def _validate_unique_key(value):
        if self.instance is None:
            try:
                self.get(**{field: value})
                raise serializers.ValidationError('%s="%s" is a duplicate' % (field, value))
            except RethinkObjectNotFound:
                pass
        return value
    return _validate_unique_key

class RethinkObjectNotFound(Exception):
    pass

class RethinkMultipleObjectsFound(Exception):
    pass

class RethinkSerializer(serializers.Serializer):
    class Meta(object):
        table_name = None
        pk_field = 'id'
        slug_field = None
        order_by = None
        abstract = False
        indices = []
        unique = []
        unique_together = []

    def __init__(self, *args, **kwargs):
        if self.Meta.slug_field:
            setattr(self, 'validate_' + self.Meta.slug_field, validate_unique_key(self, self.Meta.slug_field))
        for field in self.Meta.unique:
            setattr(self, 'validate_' + field, validate_unique_key(self, field))
        super(RethinkSerializer, self).__init__(*args, **kwargs)
        self.conn = get_connection()

    def create(self, validated_data):
        result = r.table(self.Meta.table_name).insert(validated_data, return_changes=True).run(self.conn)
        return result['changes'][0]['new_val']

    def update(self, instance, validated_data):
        queryset = r.table(self.Meta.table_name).get(instance['id'])
        if self.partial:
            queryset = queryset.update(validated_data, return_changes=True)
        else:
            queryset = queryset.replace(validated_data, return_changes=True)
        result = queryset.run(self.conn)
        if len(result['changes']) == 0:
            return validated_data
        else:
            return result['changes'][0]['new_val']

    @classmethod
    def filter(cls, *args, **fields):
        query = r.table(cls.Meta.table_name)
        try:
            reql = fields.pop('reql')
        except KeyError:
            reql = False
        if len(args) == 0 and len(fields) == 1 and fields.keys()[0] in cls.Meta.indices and not cls.Meta.order_by:
            index, value = fields.items()[0]
            query = query.get_all(value, index=index)
        else:
            if args:
                query = query.filter(*args)
            if fields:
                query = query.filter(fields)
            if cls.Meta.order_by:
                query = query.order_by(*cls.Meta.order_by)
        if reql:
            return query
        else:
            rs = query.run(get_connection())
            rs.reql_query = query
            return rs

    @classmethod
    def get(cls, *args, **fields):
        rs = cls.filter(*args, **fields)
        try:
            result = rs.next()
        except r.net.DefaultCursorEmpty:
            raise RethinkObjectNotFound("Query %s returned no objects" % rs.reql_query)
        try:
            rs.next()
            raise RethinkMultipleObjectsFound("Query %s returned more than one object" % rs.reql_query)
        except r.net.DefaultCursorEmpty:
            pass
        return result

    def delete(self):
        result = r.table(self.Meta.table_name).get(self.data[self.Meta.pk_field]).delete().run(self.conn)
        return result['deleted'] > 0

    def get_username(self):
        username = None
        if 'request' in self.context and self.context['request'].user is not None:
            username = self.context['request'].user.username
        elif 'username' in self.context:
            username = self.context['username']
        return username

    def validate(self, data):
        for group in self.Meta.unique_together:
            value = [data.get(field, self.instance.get(field, None) if self.instance is not None else None) for field in group]
            for index in self.Meta.indices:
                if isinstance(index, (tuple, list)) and index[1] == group:
                    query = r.table(self.Meta.table_name).get_all(value, index=index[0])
                    query = query.count()
                    break
            else:
                query = self.filter(dict([(field, value[i]) for i, field in enumerate(group)], reql=True))
            if self.instance is not None:
                query = query.filter(r.row[self.Meta.pk_field] != self.instance[self.Meta.pk_field])
            matched = query.run(self.conn)
            if matched > 0:
                raise serializers.ValidationError("combination of %r is not unique" % (group,))
        return data
