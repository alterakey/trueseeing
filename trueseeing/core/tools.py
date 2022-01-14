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

if TYPE_CHECKING:
  from typing import Any, Optional

def noneif(x: Any, defaulter: Any) -> Any:
  if x is not None:
    return x
  else:
    if callable(defaulter):
      return defaulter()
    else:
      return defaulter

def invoke(as_: str, redir_stderr: bool = False) -> str:
  from subprocess import run, PIPE, STDOUT
  return run(as_, shell=True, check=True, stdout=PIPE, stderr=(STDOUT if redir_stderr else None)).stdout.decode('utf-8')

def invoke_passthru(as_: str, nocheck: bool = False) -> None:
  from subprocess import run
  run(as_, shell=True, check=(not nocheck))

def try_invoke(as_: str) -> Optional[str]:
  from subprocess import CalledProcessError
  try:
    return invoke(as_)
  except CalledProcessError:
    return None
