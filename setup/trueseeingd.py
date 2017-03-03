import os
import sys
import shutil

from setuptools import setup, find_packages

install_require = [
  "wheel",
  "pycrypto",
  "websockets",
  "trueseeing-agent"
]

try:
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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
    packages=['trueseeing.api'],
    install_requires=install_require,
    entry_points = {'console_scripts':['trueseeingd = trueseeing.api.api:entry', 'trueseeing-keygen = trueseeing.api.genkey:entry']}
  )
finally:
  os.unlink('setup.py')
