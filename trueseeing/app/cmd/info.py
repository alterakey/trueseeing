from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import Command
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Dict
  from trueseeing.app.inspect import Runner
  from trueseeing.core.model.cmd import CommandEntry

class InfoCommand(Command):
  _runner: Runner

  def __init__(self, runner: Runner) -> None:
    self._runner = runner

  def get_commands(self) -> Dict[str, CommandEntry]:
    return {
      'i':dict(e=self._info, n='i[i][i]', d='print info (ii: overall, iii: detailed)'),
      'ii':dict(e=self._info2),
      'iii':dict(e=self._info3),
    }

  async def _info(self, args: deque[str], level: int = 0) -> None:
    self._runner._require_target()
    assert self._runner._target is not None

    _ = args.popleft()
    apk = self._runner._target

    import os

    boolmap = {True:'yes',False:'no','true':'yes','false':'no',1:'yes',0:'no'}
    analysisguidemap = {0: 'try ii for more info', 1: 'try iii for more info', 2: 'try iii for more info'}

    ui.info(f'info on {apk}')

    ui.info('path         {}'.format(apk))
    ui.info('size         {}'.format(os.stat(apk).st_size))

    context = self._runner._get_context(self._runner._target)

    ui.info('fp           {}'.format(context.fingerprint_of()))
    ui.info('ctx          {}'.format(context.wd))

    patched = context.has_patches()
    analyzed = context.get_analysis_level()
    if analyzed < level:
      await context.analyze(level=level)
      analyzed = level

    ui.info('has patch?   {}'.format(boolmap[patched]))
    ui.info('analyzed?    {}{}'.format(
      self._runner._decode_analysis_level(analyzed),
      ' ({})'.format(analysisguidemap[analyzed]) if analyzed < 3 else '',
    ))
    if analyzed > 0:
      store = context.store()
      manif = context.parsed_manifest()
      ui.info('pkg          {}'.format(manif.attrib['package']))
      ui.info('ver          {} ({})'.format(
        manif.attrib['{http://schemas.android.com/apk/res/android}versionName'],
        manif.attrib['{http://schemas.android.com/apk/res/android}versionCode']
      ))
      ui.info('perms        {}'.format(len(list(context.permissions_declared()))))
      ui.info('activs       {}'.format(len(list(manif.xpath('.//activity')))))
      ui.info('servs        {}'.format(len(list(manif.xpath('.//service')))))
      ui.info('recvs        {}'.format(len(list(manif.xpath('.//receiver')))))
      ui.info('provs        {}'.format(len(list(manif.xpath('.//provider')))))
      ui.info('int-flts     {}'.format(len(list(manif.xpath('.//intent-filter')))))
      if analyzed > 2:
        with store.db as c:
          for nr, in c.execute('select count(1) from classes_extends_name where extends_name regexp :pat', dict(pat='^Landroid.*Fragment(Compat)?;$')):
            ui.info('frags        {}'.format(len(list(manif.xpath('.//activity')))))
      for e in manif.xpath('.//application'):
        ui.info('debuggable?  {}'.format(boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}debuggable', 'false'), '?')))
        ui.info('backupable?  {}'.format(boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup', 'false'), '?')))
        ui.info('netsecconf?  {}'.format(boolmap.get(e.attrib.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig') is not None, '?')))
      if manif.xpath('.//uses-sdk'):
        for e in manif.xpath('.//uses-sdk'):
          ui.info('api min      {}'.format(int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))))
          ui.info('api tgt      {}'.format(int(e.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', '1'))))
      else:
        dom = context._parsed_apktool_yml()
        ui.info('api min      {} (apktool)'.format(int(dom['sdkInfo'].get('minSdkVersion', '1'))))
        ui.info('api tgt      {} (apktool)'.format(int(dom['sdkInfo'].get('targetSdkVersion', '1'))))
      if analyzed > 2:
        with store.db as c:
          for nr, in c.execute('select count(1) from analysis_issues'):
            ui.info('issues       {}{}'.format(nr, ('' if nr else ' (not scanned yet?)')))
          for nr, in c.execute('select count(1) from ops where idx=0'):
            ui.info('ops          {}'.format(nr))
          for nr, in c.execute('select count(1) from class_class_name'):
            ui.info('classes      {}'.format(nr))
          for nr, in c.execute('select count(1) from method_method_name'):
            ui.info('methods      {}'.format(nr))

  async def _info2(self, args: deque[str]) -> None:
    return await self._info(args, level=1)

  async def _info3(self, args: deque[str]) -> None:
    return await self._info(args, level=3)
