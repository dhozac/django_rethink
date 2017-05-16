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
from django.utils import timezone
from django_rethink.connection import get_connection
from django.conf import settings

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

class SimultaneousObjectManipulationException(Exception):
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

def validate_group_name(group_name):
    from django.contrib.auth.models import Group
    try:
        group = Group.objects.get(name=group_name)
        return True
    except Group.DoesNotExist:
        if hasattr(settings, 'AUTH_LDAP_SERVER_URI'):
            import ldap
            l = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            if settings.AUTH_LDAP_START_TLS:
                l.start_tls_s()
            result = settings.AUTH_LDAP_GROUP_SEARCH.search_with_additional_term_string("(cn=%s)").execute(l, filterargs=(group_name,))
            if len(result) > 0:
                return True
        raise serializers.ValidationError("group %s does not exist" % group_name)

class PermissionsSerializer(serializers.Serializer):
    read = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)
    create = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)
    write = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)

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

    def delete(self):
        result = r.table(self.Meta.table_name).get(self.data[self.Meta.pk_field]).delete().run(self.conn)
        return result['deleted'] > 0

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
            if not isinstance(rs, list):
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
                if isinstance(index, (tuple, list)) and isinstance(index[1], tuple) and map(str, index[1]) == map(str, group):
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

class HistorySerializer(RethinkSerializer):
    id = serializers.CharField(read_only=True)
    object_type = serializers.CharField(required=True)
    object = serializers.DictField(required=True)
    timestamp = serializers.DateTimeField(required=True)
    username = serializers.CharField(required=True)
    message = serializers.CharField(required=False, allow_null=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'history'
        pk_field = 'id'
        indices = [
            'object_type',
            ('object_id', r.row['object']['id']),
            ('object_type_id', (r.row['object_type'], r.row['object']['id'])),
        ]

class HistorySerializerMixin(RethinkSerializer):
    version = serializers.IntegerField(required=False)
    log = serializers.CharField(required=False)

    class Meta(RethinkSerializer.Meta):
        abstract = True

    def create(self, validated_data):
        if 'log' in validated_data:
            log = validated_data.pop('log')
        elif hasattr(self.Meta, 'log_required') and self.Meta.log_required:
            raise serializers.ValidationError("log is required")
        else:
            log = None
        if 'version' not in validated_data:
            validated_data['version'] = 1
        result = r.table(self.Meta.table_name).insert(validated_data, return_changes=True).run(self.conn)
        history = HistorySerializer(None, data={
            'object_type': self.Meta.table_name,
            'object': result['changes'][0]['new_val'].copy(),
            'username': self.get_username(),
            'timestamp': timezone.now(),
            'message': log,
        })
        history.is_valid(raise_exception=True)
        history.save()
        return result['changes'][0]['new_val']

    def update(self, instance, validated_data):
        update = dict(validated_data)
        if 'log' in update:
            log = update.pop('log')
        elif hasattr(self.Meta, 'log_required') and self.Meta.log_required:
            raise serializers.ValidationError("log is required")
        else:
            log = None
        update['version'] = validated_data['version'] + 1
        filtered = r.table(self.Meta.table_name) \
                   .get_all(instance[self.Meta.pk_field]) \
                   .filter(r.row['version'] == validated_data['version'])
        if self.partial:
            result = filtered.update(update, return_changes=True).run(self.conn)
        else:
            result = filtered.replace(update, return_changes=True).run(self.conn)
        if result['replaced'] + result['unchanged'] == 0:
            raise SimultaneousObjectManipulationException("Simultaneous object manipulation error! %s %d" % (instance[self.Meta.pk_field], instance['version']))
        if len(result['changes']) == 0:
            new_val = instance
        else:
            new_val = result['changes'][0]['new_val']
        history = HistorySerializer(None, data={
            'object_type': self.Meta.table_name,
            'object': new_val.copy(),
            'username': self.get_username(),
            'timestamp': timezone.now(),
            'message': log,
        })
        history.is_valid(raise_exception=True)
        history.save()
        return new_val

    def delete(self):
        data = self.context['request'].data
        if 'log' not in data:
            if hasattr(self.Meta, 'log_required') and self.Meta.log_required:
                raise serializers.ValidationError("'log' field is required when deleting an object")
            log = None
        else:
            log = data['log']
        result = r.table(self.Meta.table_name).get(self.instance[self.Meta.pk_field]).delete(return_changes=True).run(self.conn)
        history = HistorySerializer(None, data={
            'object_type': self.Meta.table_name,
            'object': {self.Meta.pk_field: self.instance[self.Meta.pk_field]},
            'username': self.get_username(),
            'timestamp': timezone.now(),
            'message': log,
        })
        history.is_valid(raise_exception=True)
        history.save()
        return result['deleted'] > 0
