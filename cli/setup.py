import os
import sys
import shutil

from setuptools import setup, find_packages

metadata = dict(
  name='trueseeing',
  version='2.0.3',
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

try:
  os.chdir(os.path.abspath(os.path.dirname(__file__)))

  README = open('README.rst').read()

  if sys.version_info[0:2] > (3, 4):
    shutil.copy(os.path.join(os.path.dirname(__file__), 'asyncio.cfg'), 'setup.cfg')
    setup(
      long_description=README,
      packages=find_packages(),
      python_requires='>=3.5',
      install_requires=[
        "certifi",
        "websockets"
      ],
      setup_requires=[
        "wheel",
      ],
      entry_points = {'console_scripts':['trueseeing = trueseeing.api.client:shell']},
      **metadata
    )
  else:
    shutil.copy(os.path.join(os.path.dirname(__file__), 'twisted.cfg'), 'setup.cfg')
    setup(
      long_description=README,
      packages=find_packages(),
      install_requires=[
        "autobahn",
        "twisted[tls]",
      ],
      setup_requires=[
        "wheel",
      ],
      entry_points = {'console_scripts':['trueseeing = trueseeing.api.client_twisted:shell']},
      **metadata
    )
finally:
  os.unlink('setup.cfg')
