from django.conf.urls import include, url
from django_rethink.views import *

urlpatterns = [
    url(r'^review/(?P<id>[A-Za-z0-9-]+)/?$', ReviewDetailView.as_view(), name='review_detail'),
    url(r'^review/?$', ReviewListView.as_view(), name='review_list'),
]
