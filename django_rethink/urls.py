from django.conf.urls import include, url
from django_rethink.views import *

app_name = 'django_rethink'
urlpatterns = [
    url(r'^review/(?P<id>[A-Za-z0-9-]+)/?$', ReviewDetailView.as_view(), name='review_detail'),
    url(r'^review/?$', ReviewListView.as_view(), name='review_list'),
    url(r'^history/(?P<object_type>[A-Za-z0-9-_]+)/(?P<pk>[^/]+)/?$', HistoryListView.as_view(), name='history_list'),
]
