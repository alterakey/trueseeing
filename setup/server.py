import os
import sys
import shutil

from setuptools import setup, find_packages

metadata = dict(
  name='trueseeingd',
  version='2.0.2',
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
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
  shutil.copy(os.path.join(os.path.dirname(__file__), 'server.cfg'), 'setup.cfg')
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  setup(
    long_description=README + '\n\n' + CHANGES,
    packages=find_packages('src/server'),
    package_dir={'':'src/server'},
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
finally:
  os.unlink('setup.py')
  os.unlink('setup.cfg')
