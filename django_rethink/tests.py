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

import os
import base64
import json
from django.test import TestCase, override_settings
from django.conf import settings
from django.core import management
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
import rethinkdb as r

from django_rethink.serializers import *

class TestSerializer(RethinkSerializer):
    id = serializers.CharField(required=False, read_only=True)
    permissions = PermissionsSerializer()
    class Meta(RethinkSerializer.Meta):
        table_name = 'django_rethink_test'
        indices = [
            ('permissions_read', r.row['permissions']['read']),
            ('permissions_write', r.row['permissions']['write']),
            ('permissions_create', r.row['permissions']['create']),
        ]

class TestReviewSerializer(NeedsReviewMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    field1 = serializers.CharField(required=True)
    permissions = PermissionsSerializer()
    class Meta(RethinkSerializer.Meta):
        table_name = 'django_rethink_test_reviewed'
        indices = [
            ('permissions_read', r.row['permissions']['read']),
            ('permissions_write', r.row['permissions']['write']),
            ('permissions_create', r.row['permissions']['create']),
        ]

class TestHistoryPermissionsSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    field1 = serializers.CharField(required=True)
    permissions = PermissionsSerializer()
    class Meta(RethinkSerializer.Meta):
        table_name = 'django_rethink_test_history_permissions'
        indices = [
            ('permissions_read', r.row['permissions']['read']),
            ('permissions_write', r.row['permissions']['write']),
            ('permissions_create', r.row['permissions']['create']),
        ]

class TestHistoryHasReadPermissionSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False, read_only=True)
    field1 = serializers.CharField(required=True)
    user = serializers.CharField(required=True)
    class Meta(RethinkSerializer.Meta):
        table_name = 'django_rethink_test_history_has_read_permission'
    def has_read_permission(self, user):
        return self.instance['user'] == user.username

@override_settings(
    RETHINK_DB_DB=os.environ.get('RETHINK_DB_DB', 'django_rethinkci'),
)
class APITests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(APITests, cls).setUpClass()
        cls.conn = r.connect(host=settings.RETHINK_DB_HOST, port=settings.RETHINK_DB_PORT)
        try:
            r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        except:
            pass
        r.db_create(settings.RETHINK_DB_DB).run(cls.conn)
        cls.conn.db = settings.RETHINK_DB_DB
        management.call_command('syncrethinkdb', verbosity=0)

    @classmethod
    def tearDownClass(cls):
        r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        super(APITests, cls).tearDownClass()

    def tearDown(self):
        for t in [
                "django_rethink_test",
                "history",
                "django_rethink_test_reviewed",
                "django_rethink_test_history_permissions",
                "django_rethink_test_history_has_read_permission",
            ]:
            r.table(t).delete().run(self.conn)
        super(APITests, self).tearDown()

    def create_user(self, username='tester', password='tester', is_superuser=True, groups=[], **kwargs):
        user = get_user_model().objects.create(
            username=username,
            password=make_password(password),
            is_superuser=is_superuser,
            **kwargs
        )
        for name in groups:
            group, created = Group.objects.get_or_create(name=name)
            user.groups.add(group)
        auth = "Basic %s" % (base64.b64encode("%s:%s" % (username, password)))
        return user, auth

    def test_history_no_type(self):
        super_user, super_auth = self.create_user()
        response = self.client.get(reverse('django_rethink:history_list',
            kwargs={'object_type': 'i_dont_exist', 'pk': '1'}),
            HTTP_AUTHORIZATION=super_auth
        )
        self.assertEqual(response.status_code, 404)

    def test_history_with_permissions(self):
        super_user, super_auth = self.create_user()
        luser, lauth = self.create_user(username='luser', is_superuser=False, groups=['group1'])

        serializer = TestHistoryPermissionsSerializer(None,
            data={'field1': 'test1', 'user': luser.username,
                'permissions': {'write': ['group1']}},
            context={'username': luser.username}
        )
        serializer.is_valid(raise_exception=True)
        test1 = serializer.save()

        serializer = TestHistoryPermissionsSerializer(None,
            data={'field1': 'test2', 'user': super_user.username,
                'permissions': {'write': []}},
            context={'username': super_user.username}
        )
        serializer.is_valid(raise_exception=True)
        test2 = serializer.save()

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryPermissionsSerializer.Meta.table_name,
                    'pk': test1['id'],
                }), HTTP_AUTHORIZATION=lauth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryPermissionsSerializer.Meta.table_name,
                    'pk': test2['id'],
                }), HTTP_AUTHORIZATION=lauth)
        self.assertEqual(response.status_code, 403)

    def test_history_with_has_read_permission(self):
        super_user, super_auth = self.create_user()
        luser, lauth = self.create_user(username='luser', is_superuser=False, groups=['group1'])

        serializer = TestHistoryHasReadPermissionSerializer(None,
            data={'field1': 'test1', 'user': luser.username},
            context={'username': luser.username}
        )
        serializer.is_valid(raise_exception=True)
        test1 = serializer.save()
        serializer = TestHistoryHasReadPermissionSerializer(test1,
            data={'field1': 'test1.1'}, partial=True,
            context={'username': luser.username},
        )
        serializer.is_valid(raise_exception=True)
        test1 = serializer.save()

        serializer = TestHistoryHasReadPermissionSerializer(None,
            data={'field1': 'test2', 'user': super_user.username},
            context={'username': super_user.username}
        )
        serializer.is_valid(raise_exception=True)
        test2 = serializer.save()

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryHasReadPermissionSerializer.Meta.table_name,
                    'pk': test1['id'],
                }), HTTP_AUTHORIZATION=lauth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryHasReadPermissionSerializer.Meta.table_name,
                    'pk': test2['id'],
                }), HTTP_AUTHORIZATION=lauth)
        self.assertEqual(response.status_code, 403)

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryHasReadPermissionSerializer.Meta.table_name,
                    'pk': test2['id'],
                }), HTTP_AUTHORIZATION=super_auth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

        serializer = TestHistoryHasReadPermissionSerializer(test1,
            context={'username': luser.username},
        )
        serializer.delete()

        response = self.client.get(reverse('django_rethink:history_list',
                kwargs={
                    'object_type': TestHistoryHasReadPermissionSerializer.Meta.table_name,
                    'pk': test1['id'],
                }), HTTP_AUTHORIZATION=lauth)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 3)
