import os
import sys
import shutil

from setuptools import setup, find_packages

install_require = [
  "wheel",
  "pycrypto",
  "websockets"
]

try:
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  setup(
    name='trueseeing',
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
    zip_safe=False,
    install_requires=install_require,
    entry_points = {'console_scripts':['trueseeing = trueseeing.api.client:entry']}
  )
finally:
  os.unlink('setup.py')
