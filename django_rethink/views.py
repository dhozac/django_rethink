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

import json
import rethinkdb as r
from django.views.generic.base import ContextMixin, View
from django.core.exceptions import ImproperlyConfigured
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.encoding import force_text
from rest_framework import generics, permissions
from rest_framework.exceptions import NotFound, PermissionDenied
from django_rethink.connection import get_connection
from django_rethink.apimixins import RethinkAPIMixin, RethinkSerializerPermission
from django_rethink.serializers import RethinkSerializer, HistorySerializer, ReviewSerializer

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
        except r.errors.ReqlCursorEmpty:
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

class HasReviewPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return view.get_serializer(obj).has_read_permission(request.user)

class ReviewListView(RethinkAPIMixin, generics.ListAPIView):
    pk_field = 'id'
    serializer_class = ReviewSerializer
    group_filter_fields = ['reviewers']
    permission_classes = (permissions.IsAuthenticated, HasReviewPermission)
    def default_filter_queryset(self, queryset):
        if '_include_object' in self.request.query_params:
            return queryset.merge(lambda review: {
                "orig_object": r.table(review['object_type']).get(review['object_id'])
            })
        else:
            return queryset

class ReviewDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    pk_field = 'id'
    serializer_class = ReviewSerializer
    group_filter_fields = ['reviewers']
    permission_classes = (permissions.IsAuthenticated, HasReviewPermission)

class ObjectHistoryListView(RethinkAPIMixin, generics.ListAPIView):
    serializer_class = HistorySerializer
    permission_classes = (permissions.IsAuthenticated,)
    pk_url_kwarg = None
    slug_url_kwarg = None
    def get_queryset(self):
        sub_serializer_class, object_id = self.get_serializer_and_id()
        queryset = super(ObjectHistoryListView, self).get_queryset()
        queryset = queryset.get_all(
            [sub_serializer_class.Meta.table_name, object_id],
            index="object_type_id").order_by("timestamp")

        try:
            # .count() is to ensure we get the last version before an object
            # was deleted
            last = queryset.filter(lambda r: r['object'].count() > 1) \
                .nth(-1).run(self.get_connection())
        except:
            raise NotFound()

        if hasattr(sub_serializer_class, 'has_read_permission'):
            if not sub_serializer_class(last['object']).has_read_permission(self.request.user):
                raise PermissionDenied()

        elif 'permissions' in sub_serializer_class._declared_fields:
            if not RethinkSerializerPermission().has_object_permission(self.request, self, last['object']):
                raise PermissionDenied()

        else:
            raise NotFound()

        return queryset

class HistoryListView(ObjectHistoryListView):
    def get_serializer_and_id(self):
        from django_rethink.tasks import all_subclasses
        for sub_serializer_class in all_subclasses(RethinkSerializer):
            if sub_serializer_class.Meta.table_name == self.kwargs['object_type']:
                break
        else:
            raise NotFound()
        return (sub_serializer_class, self.kwargs['pk'])
