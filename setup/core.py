import os
import sys
import shutil

from setuptools import setup, find_packages

try:
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
  shutil.copy(os.path.join(os.path.dirname(__file__), 'common.cfg'), 'setup.cfg')
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  setup(
    name='trueseeing-core',
    version='2.0.1',
    description='Trueseeing is Android vulnerability scanner and peneration test framework.',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
      "Programming Language :: Python",
      "Programming Language :: Java",
    ],
    author='Takahiro Yoshimura',
    author_email='takahiro_y@monolithworks.co.jp',
    url='https://github.com/taky/trueseeing',
    keywords='android java security pentest hacking',
    packages=find_packages('src/core'),
    package_dir={'':'src/core'},
    package_data={'trueseeing':['libs/*.jar', 'libs/*.txt', 'libs/*.sql', 'template/*']},
    include_package_data=True,
    zip_safe=False,
    install_requires=[
      "lxml",
      "jinja2"
    ],
    setup_requires=[
      "wheel",
    ],
  )
finally:
  os.unlink('setup.py')
  os.unlink('setup.cfg')
