from django.conf.urls import include, url

urlpatterns = [
    url(r'', include('django_rethink.urls', namespace='django_rethink')),
]
