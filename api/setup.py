import os
import sys
import shutil

from setuptools import setup, find_packages

metadata = dict(
  name='trueseeingd',
  version='2.0.4',
  description='Trueseeing is a fast, accurate, and resillient vulnerability scanner for Android apps.',
  classifiers=[
    "Topic :: Security",
    "Operating System :: Android",
    "Programming Language :: Java",
  ],
  author='Takahiro Yoshimura',
  author_email='takahiro_y@monolithworks.co.jp',
  url='https://github.com/taky/trueseeing',
  keywords='android java security pentest hacking',
)

README = open('README.rst').read()

setup(
  long_description=README,
  packages=find_packages(),
  python_requires='>=3.5',
  install_requires=[
    "pycrypto",
    "websockets",
    "trueseeing-core"
  ],
  setup_requires=[
    'wheel'
  ],
  entry_points = {'console_scripts':['trueseeingd = trueseeing.api.server:shell', 'trueseeing-keygen = trueseeing.api.genkey:shell', 'agent = trueseeing.api.agent:shell']},
  **metadata
)
