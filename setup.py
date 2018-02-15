#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='django_rethink',
      version='0.3.11',
      description='Library to use RethinkDB with Django REST framework',
      author='Klarna IT Operations Core Services',
      author_email='itops.core-services@klarna.com',
      url='',
      packages=['django_rethink', 'django_rethink.management', 'django_rethink.management.commands'],
      install_requires=map(lambda x: re.sub(r".*#egg=(.*)", lambda m: m.group(1), x.strip()), open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).readlines()),
      include_package_data=True,
      zip_safe=True,
)
