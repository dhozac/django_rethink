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

from rest_framework import serializers
import rethinkdb as r
import six
from django_rethink.connection import get_connection

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

def dict_merge(dict1, dict2):
    if dict1 is None:
        return dict2.copy()
    elif dict2 is None:
        return dict1.copy()
    elif not isinstance(dict1, dict) or not isinstance(dict2, dict):
        raise Exception("Attempting to dict_merge non-dicts: %r %r" % (dict1, dict2))
    d = dict1.copy()
    for key in dict2:
        if key in d and isinstance(d[key], dict):
            d[key] = dict_merge(d[key], dict2[key])
        else:
            d[key] = dict2[key]
    return d


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
                    break
            else:
                query = self.filter(dict([(field, value[i]) for i, field in enumerate(group)]), reql=True)
            if self.instance is not None:
                query = query.filter(r.row[self.Meta.pk_field] != self.instance[self.Meta.pk_field])
            query = query.count()
            matched = query.run(self.conn)
            if matched > 0:
                raise serializers.ValidationError("combination of %r is not unique" % (group,))
        return data

    def get_updated_object(self, data):
        if self.partial:
            return dict_merge(self.instance, data)
        else:
            return data
