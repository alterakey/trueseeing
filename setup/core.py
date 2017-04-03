import os
import sys
import shutil

from setuptools import setup, find_packages

metadata = dict(
  name='trueseeing-core',
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
  shutil.copy(os.path.join(os.path.dirname(__file__), 'common.cfg'), 'setup.cfg')
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  setup(
    long_description=README + '\n\n' + CHANGES,
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
    **metadata
  )
finally:
  os.unlink('setup.py')
  os.unlink('setup.cfg')
