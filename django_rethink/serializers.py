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

import uuid
import rethinkdb as r
import deepdiff
from django.utils import timezone
from rest_framework import serializers
from rest_framework.reverse import reverse
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

def validate_username(username):
    from django.contrib.auth import get_user_model
    model = get_user_model()
    try:
        user = model.objects.get(username=username)
        return True
    except model.DoesNotExist:
        if hasattr(settings, 'AUTH_LDAP_SERVER_URI'):
            l = ldap.initialize(settings.AUTH_LDAP_SERVER_URI)
            if settings.AUTH_LDAP_START_TLS:
                l.start_tls_s()
            result = settings.AUTH_LDAP_USER_SEARCH.execute(l, filterargs=(username,))
            if len(result) > 0:
                return True
        raise serializers.ValidationError("user %s does not exist" % username)

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

class PermissionsSerializer(serializers.Serializer):
    read = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)
    create = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)
    write = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), allow_empty=True, required=False)

class RethinkSerializer(serializers.Serializer):
    link = serializers.URLField(read_only=True)
    url_field_name = 'link'

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
        except r.errors.ReqlCursorEmpty:
            raise RethinkObjectNotFound("Query %s returned no objects" % rs.reql_query)
        try:
            rs.next()
            raise RethinkMultipleObjectsFound("Query %s returned more than one object" % rs.reql_query)
        except r.errors.ReqlCursorEmpty:
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

    def to_representation(self, instance):
        ret = super(RethinkSerializer, self).to_representation(instance)
        link = self.create_link(instance)
        if link is not None:
            ret['link'] = link
        return ret

    def create_link(self, instance):
        return None

class HistorySerializer(RethinkSerializer):
    id = serializers.CharField(read_only=True)
    object_type = serializers.CharField(required=True)
    object = serializers.DictField(required=True)
    timestamp = serializers.DateTimeField(required=True)
    username = serializers.CharField(required=False, allow_null=True)
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
        version_required = True

    def validate_version(self, value):
        if self.instance is not None and value != self.instance['version']:
            raise serializers.ValidationError("version is not the expected %d" % self.instance['version'])
        return value

    def validate(self, data):
        data = super(HistorySerializerMixin, self).validate(data)
        if hasattr(self.Meta, 'log_required') and self.Meta.log_required and 'log' not in data:
            raise serializers.ValidationError("log is required")
        if hasattr(self.Meta, 'version_required') and self.Meta.version_required and 'version' not in data:
            raise serializers.ValidationError("version is required")
        return data

    def create(self, validated_data):
        if 'log' in validated_data:
            log = validated_data.pop('log')
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
        else:
            log = None
        if 'version' in validated_data:
            old_version = validated_data['version']
        else:
            old_version = instance['version']
        update['version'] = old_version + 1
        filtered = r.table(self.Meta.table_name) \
                   .get_all(instance[self.Meta.pk_field]) \
                   .filter(r.row['version'] == old_version)
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
        if 'request' in self.context:
            data = self.context['request'].data
            if 'log' not in data:
                if hasattr(self.Meta, 'log_required') and self.Meta.log_required:
                    raise serializers.ValidationError("'log' field is required when deleting an object")
                log = None
            else:
                log = data['log']
        elif 'log' in self.context:
            log = self.context['log']
        else:
            log = None
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

class LockSerializer(RethinkSerializer):
    id = serializers.CharField(read_only=True)
    token = serializers.CharField(required=True)
    server = serializers.CharField(required=True)
    timestamp = serializers.DateTimeField(required=True)

    class Meta(RethinkSerializer.Meta):
        table_name = 'locks'

class ReviewSerializer(HistorySerializerMixin):
    id = serializers.CharField(read_only=True)
    created = serializers.DateTimeField(default=serializers.CreateOnlyDefault(timezone.now))
    updated = serializers.DateTimeField(default=timezone.now)
    state = serializers.ChoiceField(choices=['pending', 'approved', 'rejected', 'invalidated', 'executed'], required=True)
    submitter = serializers.CharField(validators=[validate_username], required=True)
    reviewers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=True)
    approvals_required = serializers.IntegerField(default=1, required=False)
    approvals = serializers.ListField(child=serializers.CharField(validators=[validate_username]), required=False)

    is_partial = serializers.BooleanField(required=True)
    is_delete = serializers.BooleanField(required=False)
    object_type = serializers.CharField(required=True)
    object_id = serializers.CharField(required=True)
    object = serializers.DictField(required=True)

    orig_object = serializers.ReadOnlyField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'reviews'
        indices = [
            'submitter',
            ('reviewers', {'multi': True}),
        ]

    def has_read_permission(self, user, user_groups=None):
        if user_groups is None:
            user_groups = set(user.groups.all().values_list('name', flat=True))
        if user.is_superuser:
            return True
        if hasattr(user, 'is_global_readonly') and user.is_global_readonly:
            return True

        reviewers = set(self.instance.get('reviewers', []))
        if len(user_groups.intersection(reviewers)) > 0:
            return True

        return False

    # Write permissions are handled in validate()
    has_write_permission = has_read_permission

    def update(self, old_instance, validated_data):
        new_instance = super(ReviewSerializer, self).update(old_instance, validated_data)
        if old_instance['state'] == 'approved' and new_instance['state'] == 'executed':
            from django_rethink.tasks import review_execute
            review_execute.apply_async((new_instance,))
        return new_instance

    def validate(self, data):
        if ('request' in self.context and
            self.context['request'].user is not None):
            user = self.context['request'].user
            user_groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
        else:
            user = None
            user_groups = set([])

        if self.instance is None:
            data['state'] = 'pending'
            if user is not None:
                data['submitter'] = user.username
            data['approvals'] = []
            return data

        diff = deepdiff.DeepDiff(dict_merge(data, self.instance) if self.partial else data, self.instance, view='tree')
        for read_only_field in ['id', 'created', 'submitter', 'object_type', 'object_id', 'object']:
            for change in diff.values():
                for dl in change:
                    if ((dl.all_up.t1_child_rel is not None and
                            dl.all_up.t1_child_rel.param == read_only_field) or
                            (dl.all_up.t2_child_rel is not None and
                            dl.all_up.t2_child_rel.param == read_only_field)):
                        raise serializers.ValidationError("%s is read-only after creation" % read_only_field)

        new_approvals = set(data.get('approvals', [])).difference(set(self.instance['approvals']))
        if len(new_approvals) > 0:
            if new_approvals != set([user.username]):
                raise serializers.ValidationError("attempted to add %r approvals, you can only add your own" % new_approvals)
            if len(user_groups.intersection(set(self.instance['reviewers']))) == 0 and not user.is_superuser:
                raise serializers.ValidationError("%s is not allowed to approve this review, must be member of %r" % (user.username, self.instance['reviewers']))
            if user.username == self.instance['submitter']:
                raise serializers.ValidationError("cannot approve your own request")

        if (self.instance['state'] == 'pending' and
            len(data.get('approvals', [])) >= self.instance.get('approvals_required', 1)):
            data['state'] = 'approved'

        STATE_TRANSITIONS = {
            'pending': ['approved', 'rejected', 'invalidated'],
            'approved': ['executed', 'rejected', 'invalidated'],
            'rejected': ['pending'],
            'invalidated': [],
            'executed': [],
        }
        if 'state' in data and data['state'] not in STATE_TRANSITIONS[self.instance['state']]:
            raise serializers.ValidationError("transition to state %s from %s is invalid" % (data['state'], self.instance['state']))

        return data

    def create_link(self, instance):
        return reverse('django_rethink:review_detail', kwargs={'id': instance['id']}, request=self.context.get('request'))

class NeedsReviewMixin(object):
    def get_reviewers(self, instance, data):
        return instance.get('permissions', {}).get('write', [])

    def needs_review(self, instance, data):
        if instance is None:
            return False
        return instance.get(self.Meta.needs_review_field, False)

    def create_or_update(self, supered, instance, data, is_delete=False):
        if (self.needs_review(instance, data) and
                self.get_username() is not None and
                not self.context.get('reviewed', False)):
            review = ReviewSerializer(None, data={
                'state': 'pending',
                'submitter': self.get_username(),
                'reviewers': self.get_reviewers(instance, data),
                'is_partial': self.partial,
                'is_delete': is_delete,
                'object_type': self.Meta.table_name,
                'object_id': instance[self.Meta.pk_field] if instance else str(uuid.uuid4()),
                'object': data,
            }, context=self.context)
            review.is_valid(raise_exception=True)
            result = review.save()
            raise serializers.ValidationError(["review created", result['id']])
        return supered()

    def create(self, data):
        return self.create_or_update(lambda: super(NeedsReviewMixin, self).create(data), None, data)

    def update(self, instance, data):
        return self.create_or_update(lambda: super(NeedsReviewMixin, self).update(instance, data), instance, data)

    def delete(self):
        return self.create_or_update(lambda: super(NeedsReviewMixin, self).delete(), self.instance, {}, is_delete=True)
