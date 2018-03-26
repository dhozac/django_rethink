#!/usr/bin/env python

from setuptools import setup
import os
import re

setup(name='django_rethink',
      version='0.3.16',
      license='Apache Software License',
      description='Library to use RethinkDB with Django REST framework',
      author='Klarna Bank AB',
      author_email='daniel.zakrisson@klarna.com',
      url='https://github.com/dhozac/django_rethink',
      packages=['django_rethink', 'django_rethink.management', 'django_rethink.management.commands'],
      install_requires=map(lambda x: re.sub(r".*#egg=(.*)", lambda m: m.group(1), x.strip()), open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).readlines()),
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
