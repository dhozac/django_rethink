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
import json
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404
from django.utils.translation import ugettext as _
from rest_framework import serializers
from django_rethink.connection import get_connection

class RethinkAPIMixin(object):
    rethink_conn = None
    pk_url_kwarg = "id"
    slug_url_kwarg = "slug"
    queryset = None
    pk_index_name = None
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
