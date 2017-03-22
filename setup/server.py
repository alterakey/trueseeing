import os
import sys
import shutil

from setuptools import setup, find_packages

try:
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
  shutil.copy(os.path.join(os.path.dirname(__file__), 'server.cfg'), 'setup.cfg')
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  setup(
    name='trueseeingd',
    version='2.0.0',
    description='Trueseeing is Android vulnerability scanner and peneration test framework.',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
      "Programming Language :: Python",
      "Programming Language :: Java",
    ],
    author='Takahiro Yoshimura',
    author_email='altakey@gmail.com',
    url='https://github.com/taky/trueseeing',
    keywords='android java security pentest hacking',
    packages=find_packages('src/server'),
    package_dir={'':'src/server'},
    install_requires=[
      "pycrypto",
      "websockets",
      "trueseeing-agent"
    ],
    setup_requires=[
      'wheel'
    ],
    entry_points = {'console_scripts':['trueseeingd = trueseeing.api.server:shell', 'trueseeing-keygen = trueseeing.api.genkey:shell']}
  )
finally:
  os.unlink('setup.py')
  os.unlink('setup.cfg')
