# -*- coding: utf-8 -*-
# Trueseeing: Non-decompiling Android application vulnerability scanner
# Copyright (C) 2017-22 Takahiro Yoshimura <takahiro_y@monolithworks.co.jp>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import annotations
from typing import TYPE_CHECKING

import sys

if TYPE_CHECKING:
  from typing import NoReturn, ClassVar
  from typing_extensions import Final

class UI:
  DEBUG: Final = 0
  INFO: Final = 1
  WARN: Final = 2
  ERROR: Final = 3
  CRITICAL: Final = 4
  FATAL: Final = 5

  level = DEBUG

  def fatal(self, msg: str, nl: bool = True) -> NoReturn:
    self.stderr(f'fatal: {msg}', nl=nl)
    sys.exit(2)

  def critical(self, msg: str, nl: bool = True) -> None:
    if self.level <= self.CRITICAL:
      self.stderr(msg, nl=nl)

  def error(self, msg: str, nl: bool = True) -> None:
    if self.level <= self.ERROR:
      self.stderr(msg, nl=nl)

  def warn(self, msg: str, nl: bool = True) -> None:
    if self.level <= self.WARN:
      self.stderr(msg, nl=nl)

  def info(self, msg: str, nl: bool = True) -> None:
    if self.level <= self.INFO:
      self.stderr(msg, nl=nl)

  def debug(self, msg: str, nl: bool = True) -> None:
    if self.level <= self.DEBUG:
      self.stderr(msg, nl=nl)

  def stdout(self, msg: str, nl: bool = True) -> None:
    sys.stdout.write(msg)
    if nl:
      sys.stdout.write('\n')

  def stderr(self, msg: str, nl: bool = True) -> None:
    sys.stderr.write(msg)
    if nl:
      sys.stderr.write('\n')

ui = UI()
