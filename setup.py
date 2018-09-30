import os
import sys
import shutil

from setuptools import setup, find_packages

metadata = dict(
  name='trueseeing',
  version='2.0.10',
  description='Trueseeing is a non-decompiling Android application vulnerability scanner.',
  classifiers=[
    "Topic :: Security",
    "Operating System :: Android",
    "Programming Language :: Java",
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"
  ],
  author='Takahiro Yoshimura',
  author_email='takahiro_y@monolithworks.co.jp',
  url='https://github.com/monolithworks/trueseeing',
  keywords='android java security pentest hacking',
)

README = open('README.rst').read()

setup(
  long_description=README,
  packages=find_packages(),
  package_data={'trueseeing':['libs/*.jar', 'libs/*.txt', 'libs/*.sql', 'template/*']},
  include_package_data=True,
  zip_safe=False,
  install_requires=[
    "lxml",
    "jinja2",
    "ipython"
  ],
  setup_requires=[
    "wheel",
  ],
  entry_points = {'console_scripts':['trueseeing = trueseeing.shell:shell']},
  **metadata
)
