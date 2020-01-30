#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='django_rethink',
      version='0.5.1',
      license='Apache Software License',
      description='Library to use RethinkDB with Django REST framework',
      author='Klarna Bank AB',
      author_email='daniel.zakrisson@klarna.com',
      url='https://github.com/dhozac/django_rethink',
      packages=['django_rethink', 'django_rethink.management', 'django_rethink.management.commands'],
      install_requires=[
          'celery',
          'djangorestframework>3.4.0',
          'rethinkdb',
          'deepdiff>3.2.0',
      ],
      include_package_data=True,
      zip_safe=True,
      classifiers=[
          'Development Status :: 6 - Mature',
          'Environment :: Web Environment',
          'Framework :: Django :: 1.11',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
      ],
)
