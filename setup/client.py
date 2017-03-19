import os
import sys
import shutil

from setuptools import setup, find_packages

try:
  os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
  shutil.copy(__file__, 'setup.py')
  sys.argv[0] = 'setup.py'

  README = open('README.md').read()
  CHANGES = open('CHANGES.md').read()

  if sys.version_info[0:2] > (3, 4):
    shutil.copy(os.path.join(os.path.dirname(__file__), 'client.cfg'), 'setup.cfg')
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
      packages=find_packages('src/client'),
      package_dir={'':'src/client'},
      install_requires=[
        "certifi",
        "websockets"
      ],
      setup_requires=[
        "wheel",
      ],
      entry_points = {'console_scripts':['trueseeing = trueseeing.api.client:shell']}
    )
  else:
    shutil.copy(os.path.join(os.path.dirname(__file__), 'client_twisted.cfg'), 'setup.cfg')
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
      packages=find_packages('src/client'),
      package_dir={'':'src/client'},
      install_requires=[
        "autobahn",
        "twisted[tls]",
      ],
      setup_requires=[
        "wheel",
      ],
      entry_points = {'console_scripts':['trueseeing = trueseeing.api.client_twisted:shell']}
    )
finally:
  os.unlink('setup.py')
  os.unlink('setup.cfg')
