from __future__ import annotations
from typing import TYPE_CHECKING

from collections import deque

from trueseeing.core.model.cmd import CommandMixin
from trueseeing.core.ui import ui

if TYPE_CHECKING:
  from typing import Any, Optional, Dict, Mapping, List, Iterator, Tuple
  from trueseeing.api import CommandHelper, Command, CommandMap, OptionMap
  from trueseeing.core.android.context import APKContext
  from trueseeing.core.android.model import XAPKManifest

class EngageCommand(CommandMixin):
  def __init__(self, helper: CommandHelper) -> None:
    self._helper = helper

  @staticmethod
  def create(helper: CommandHelper) -> Command:
    return EngageCommand(helper)

  def get_commands(self) -> CommandMap:
    return {
      'xtq':dict(e=self._engage_tamper_discard, n='xtq', d='engage: discard changes', t={'apk'}),
      'xtx':dict(e=self._engage_tamper_apply, n='xtx[!]', d='engage: apply and rebuild apk', t={'apk'}),
      'xtx!':dict(e=self._engage_tamper_apply, t={'apk'}),
      'xtf':dict(e=self._engage_tamper_inject_frida, n='xtf[!] [config]', d='engage; inject frida gadget', t={'apk'}),
      'xtf!':dict(e=self._engage_tamper_inject_frida, t={'apk'}),
      'xtfs':dict(e=self._engage_tamper_inject_frida_scriptdir, n='xtfs[!] [path]', d='engage; inject frida gadget in script dir mode', t={'apk'}),
      'xtfs!':dict(e=self._engage_tamper_inject_frida_scriptdir, t={'apk'}),
      'xtn':dict(e=self._engage_tamper_disable_pinning, n='xtn', d='engage: patch NSC to disable SSL/TLS pinning', t={'apk'}),
      'xtd':dict(e=self._engage_tamper_enable_debug, n='xtd', d='engage: make debuggable', t={'apk'}),
      'xtb':dict(e=self._engage_tamper_enable_backup, n='xtb', d='engage: make backupable', t={'apk'}),
      'xtt':dict(e=self._engage_tamper_patch_target_api_level, n='xtt[!] <api level>', d='engage: patch target api level', t={'apk'}),
      'xtt!':dict(e=self._engage_tamper_patch_target_api_level, t={'apk'}),
      'xco':dict(e=self._engage_device_copyout, n='xco[!] package [data.tar]', d='engage: copy-out package data', t={'apk'}),
      'xco!':dict(e=self._engage_device_copyout, t={'apk'}),
      'xci':dict(e=self._engage_device_copyin, n='xci[!] package [data.tar]', d='engage: copy-in package data', t={'apk'}),
      'xci!':dict(e=self._engage_device_copyin, t={'apk'}),
      'xpd':dict(e=self._engage_deploy_package, n='xpd[!]', d='engage: deploy target package', t={'apk'}),
      'xpd!':dict(e=self._engage_deploy_package, t={'apk'}),
      'xpu':dict(e=self._engage_undeploy_package, n='xpu', d='engage: remove target package', t={'apk'}),
      'xz':dict(e=self._engage_fuzz_intent, n='xz[!] "am-cmdline-template" [output.txt]', d='engage: fuzz intent', t={'apk'}),
      'xz!':dict(e=self._engage_fuzz_intent, t={'apk'}),
      'xzr':dict(e=self._engage_fuzz_command, n='xzr[!] "cmdline-template" [output.txt]', d='engage: fuzz cmdline', t={'apk'}),
      'xzr!':dict(e=self._engage_fuzz_command, t={'apk'}),
      'xg':dict(e=self._engage_grab_package, n='xg[!] package [output.apk]', d='engage: grab package', t={'apk'}),
      'xg!':dict(e=self._engage_grab_package, t={'apk'}),
      'xs':dict(e=self._engage_frida_start_server, n='xs[!] [config]', d='engage: start frida-server (!: force)', t={'apk'}),
      'xs!':dict(e=self._engage_frida_start_server, t={'apk'}),
      'xk':dict(e=self._engage_frida_kill_server, n='xk', d='engage: kill frida server', t={'apk'}),
    }

  def get_options(self) -> OptionMap:
    return {
      'vers':dict(n='vers=X.Y.Z', d='specify frida-gadget version to use [xf,xfs]', t={'apk'}),
      'w':dict(n='wNAME=FN', d='wordlist, use as {NAME} [xz]', t={'apk'}),
    }

  async def _engage_tamper_discard(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    _ = args.popleft()

    import time

    at = time.time()

    context = await self._helper.get_context().require_type('apk').analyze(level=2)
    with context.store().query().scoped() as q:
      if not q.patch_exists(None):
        ui.fatal('nothing to discard')
      ui.info('discarding patches to {apk}'.format(apk=apk))
      q.patch_clear()

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_apply(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    cmd = args.popleft()

    import os
    import time
    from tempfile import TemporaryDirectory
    from trueseeing.core.android.asm import APKAssembler
    from trueseeing.core.android.tools import move_apk

    if apk.endswith('.xapk'):
      ui.warn('patching xapk as merged apk')
      apk = apk.replace('.xapk', '.apk')

    origapk = apk.replace('.apk', '.apk.orig')

    if os.path.exists(origapk) and not cmd.endswith('!'):
      ui.fatal('backup file exists; force (!) to overwrite')

    at = time.time()

    context = await self._helper.get_context().require_type('apk').analyze(level=2)
    with context.store().query().scoped() as q:
      if not q.patch_exists(None):
        ui.fatal('nothing to apply')

      with TemporaryDirectory(dir=context.wd) as td:
        ui.info('applying patches to {apk}'.format(apk=apk))
        root = os.path.join(td, 'f')

        for path,blob in q.file_enum(None, patched=True):
          target = os.path.join(root, *path.split('/'))
          os.makedirs(os.path.dirname(target), exist_ok=True)
          with open(target, 'wb') as f:
            f.write(blob)

        outapk, outsig = await APKAssembler.assemble_from_path(td, root)

        if os.path.exists(apk):
          move_apk(apk, origapk)

        move_apk(outapk, apk)

      q.patch_clear()

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_disable_pinning(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    _ = args.popleft()

    import time
    import random
    from importlib.resources import files

    ui.info('disabling declarative TLS pinning {apk}'.format(apk=apk))

    at = time.time()
    context = await self._helper.get_context().require_type('apk').analyze(level=2)
    with context.store().query().scoped() as q:
      key = 'nsc{:04x}'.format(random.randint(0, 2**16))

      path = 'AndroidManifest.xml'
      blob = q.file_get(path, patched=True)
      assert blob is not None

      manif = self._parsed_manifest(blob)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}usesCleartextTraffic'] = "true"
        e.attrib['{http://schemas.android.com/apk/res/android}networkSecurityConfig'] = f'@xml/{key}'
      q.patch_put(path, self._manifest_as_xml(manif), z=True)

      # XXX
      path = f'resources/package_1/res/xml/{key}.xml'
      q.patch_put(path, (files('trueseeing')/'libs'/'android'/'nsc.xml').read_bytes(), z=True)

      # XXX
      import lxml.etree as ET
      path = 'resources/package_1/res/values/public.xml'
      root = ET.fromstring(q.file_get(path, patched=True), parser=ET.XMLParser(recover=True))
      if root.xpath('./public[@type="xml"]'):
        maxid = max(int(e.attrib["id"], 16) for e in root.xpath('./public[@type="xml"]'))
        n = ET.SubElement(root, 'public')
        n.attrib['id'] = f'0x{maxid+1:08x}'
        n.attrib['type'] = 'xml'
        n.attrib['name'] = key
      else:
        maxid = (max(int(e.attrib["id"], 16) for e in root.xpath('./public')) & 0xffff0000)
        n = ET.SubElement(root, 'public')
        n.attrib['id'] = f'0x{maxid+0x10000:08x}'
        n.attrib['type'] = 'xml'
        n.attrib['name'] = key
      q.patch_put(path, ET.tostring(root),z=True)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_enable_debug(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    _ = args.popleft()

    import time

    ui.info('enabling debug {apk}'.format(apk=apk))

    at = time.time()
    context = await self._helper.get_context().require_type('apk').analyze(level=2)
    with context.store().query().scoped() as q:
      path = 'AndroidManifest.xml'
      blob = q.file_get(path, patched=True)
      assert blob is not None
      manif = self._parsed_manifest(blob)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = "true"
      q.patch_put(path, self._manifest_as_xml(manif), z=True)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_enable_backup(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    _ = args.popleft()

    import time

    ui.info('enabling full backup {apk}'.format(apk=apk))

    at = time.time()
    context = await self._helper.get_context().require_type('apk').analyze(level=1)
    with context.store().query().scoped() as q:
      path = 'AndroidManifest.xml'
      blob = q.file_get(path, patched=True)
      assert blob is not None
      manif = self._parsed_manifest(blob)
      for e in manif.xpath('.//application'):
        e.attrib['{http://schemas.android.com/apk/res/android}allowBackup'] = "true"
        if '{http://schemas.android.com/apk/res/android}fullBackupContent' in e.attrib:
          del e.attrib['{http://schemas.android.com/apk/res/android}fullBackupContent']
      q.patch_put(path, self._manifest_as_xml(manif), z=True)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_patch_target_api_level(self, args: deque[str]) -> None:
    apk = self._helper.require_target()

    cmd = args.popleft()

    try:
      level = int(args.popleft())
    except (IndexError, ValueError):
      ui.fatal('need API level')

    import time

    ui.info('retargetting API level {level} {apk}'.format(level=level, apk=apk))

    at = time.time()

    context = await self._helper.get_context().require_type('apk').analyze(level=2)
    with context.store().query().scoped() as q:
      path = 'AndroidManifest.xml'
      blob = q.file_get(path, patched=True)
      assert blob is not None
      manif = self._parsed_manifest(blob)
      for e in manif.xpath('.//uses-sdk'):
        e.attrib['{http://schemas.android.com/apk/res/android}targetSdkVersion'] = str(level)
        minLevel = int(e.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion', '1'))
        if level < minLevel:
          if not cmd.endswith('!'):
            ui.fatal('cannot target API level below requirement ({minlv}); force (!) to downgrade altogether'.format(minlv=minLevel))
          else:
            ui.warn('downgrading the requirement')
            e.attrib['{http://schemas.android.com/apk/res/android}minSdkVersion'] = str(level)
      q.patch_put(path, self._manifest_as_xml(manif), z=True)

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  # XXX: long and ugly
  async def _engage_tamper_inject_frida(self, args: deque[str], script_dir_mode: bool = False) -> None:
    configfn: Optional[str] = None
    config_override: Optional[str] = None
    dev_frida_dir: Optional[str] = None

    apk = self._helper.require_target()

    cmd = args.popleft()

    vers = None
    for optname, optvalue in self._helper.get_effective_options(self._helper.get_modifiers(args)).items():
      if optname == 'vers':
        vers = optvalue
    if not vers:
      try:
        vers = await self._determine_recent_frida_gadget()
      except InvalidResponseError:
        ui.fatal('cannot determine recent frida-gadget version (try @o:vers=X.Y.Z)')

    assert vers is not None

    if args:
      if not args[0].startswith('@'):
        if not script_dir_mode:
          configfn = args.popleft()
        else:
          dev_frida_dir = args.popleft()

    import json
    import os
    import re
    import random
    import time
    import lief
    import tempfile
    from importlib.resources import files, as_file
    from jinja2 import Environment, FileSystemLoader

    ui.info('injecting frida-gadget {apk} [{vers}]'.format(apk=apk, vers=vers))

    at = time.time()
    gadget_map = await self._prepare_frida_gadget(vers=vers)
    context: APKContext = await self._helper.get_context().require_type('apk').analyze(level=3)

    if script_dir_mode:
      from trueseeing.core.env import get_device_frida_dir

      if not dev_frida_dir:
        dev_frida_dir = get_device_frida_dir(context.get_package_name())

      assert dev_frida_dir
      ui.info(f'using frida script directory: {dev_frida_dir}')

      with as_file(files('trueseeing')/'libs'/'android') as libpath:
        env = Environment(loader=FileSystemLoader(libpath), autoescape=True, trim_blocks=True, lstrip_blocks=True)
        config_override = env.get_template('frida-scriptdir.config').render(path=dev_frida_dir)

    with context.store().query().scoped() as q:
      thunk_pat = r'p[0-9a-f]{4}\.App[0-9a-f]{8}'
      pkg = 'p{:04x}'.format(random.randint(0, 2**16 - 1))
      key = 'App{:08x}'.format(random.randint(0, 2**32 - 1))
      lib = '{:08x}'.format(random.randint(0, 2**32 - 1))

      ui.info('adding gadget{}'.format('/config' if (configfn or config_override) else ''))
      store_map_fn = 'uncompressed-files.json'
      store_map_json = q.file_get(store_map_fn, patched=True)
      assert store_map_json
      store_map = json.loads(store_map_json)
      should_store = any([l.startswith('lib/') for l in store_map['paths']])
      for arch, distfn in gadget_map.items():
        from lzma import decompress
        memberfn = f'lib/{arch}/lib{lib}.so'
        with open(distfn, 'rb') as f:
          q.patch_put(f'root/{memberfn}', decompress(f.read()), z=True)
        if should_store:
          store_map['paths'].append(memberfn)

        if configfn or config_override:
          memberfn = f'lib/{arch}/lib{lib}.config.so'
          if config_override:
            config = config_override
          else:
            assert configfn # XXX
            with open(configfn, 'r') as f:
              config = f.read()
          q.patch_put(f'root/{memberfn}', config.encode('utf-8'), z=True)
          if should_store:
            store_map['paths'].append(memberfn)

      if should_store:
        q.patch_put(store_map_fn, json.dumps(store_map).encode('utf-8'), z=True)

      ui.info('patching ELF')
      with tempfile.TemporaryDirectory(dir=context.wd) as td:
        for n, c in q.file_enum(r'^root/lib/lib.*\.so', patched=True, regex=True):
          sopath = os.path.join(td, os.path.basename(n))
          with open(sopath, 'wb') as f0:
            f0.write(c)
          so = lief.ELF.parse(sopath)
          if not so:
            ui.warn(f'file is not ELF, ignored: {n}')
          else:
            so.add_library(f'lib{lib}.so')
            so.write(sopath)
            with open(sopath, 'rb') as f1:
              q.patch_put(n, f1.read(), z=True)

      ui.info('patching dex')

      path = 'AndroidManifest.xml'
      blob = q.file_get(path, patched=True)
      assert blob is not None
      manif = self._parsed_manifest(blob)

      try:
        last_block = max([int(n) for n in set([re.match(r'smali/classes([0-9]+)', fn).group(1) for fn in q.file_find('^smali/classes[0-9]+', regex=True)])]) # type: ignore[union-attr]
        ui.info(f'detected last dex block id: {last_block}')
      except ValueError:
        ui.warn('cannot determine last dex block id, assuming single block')
        last_block = None

      ns = dict(android='http://schemas.android.com/apk/res/android')
      ns_android = ns['android']

      if not manif.xpath('./uses-permission[@android:name="android.permission.INTERNET"]', namespaces=ns):
        ui.warn('adding necessary permission: INTERNET')
        import lxml.etree as ET
        el = ET.Element('uses-permission')
        el.attrib[f'{{{ns_android}}}name'] = 'android.permission.INTERNET'
        manif.insert(0, el)

      cn = f'{pkg}.{key}'
      for e in manif.xpath('.//application'):
        base = e.attrib.get(f'{{{ns_android}}}name', 'android.app.Application')
        e.attrib[f'{{{ns_android}}}name'] = cn

        if configfn or config_override:
          ui.warn('enabling legacy behavior on native library packaging')
          e.attrib[f'{{{ns_android}}}extractNativeLibs'] = 'true'

        if not base.startswith('android.'):
          if re.fullmatch(thunk_pat, base):
            if not cmd.endswith('!'):
              ui.fatal('target appears to already injected; force (!) to do anyway')

          appcl: Dict[str, bytes] = dict()
          for n, c in q.file_enum(self._as_smali_file_pattern(base), patched=True, regex=True):
            appcl[n] = c
          if len(appcl) != 1:
            if len(appcl):
              ui.warn('found multiple candidates of application classses')
            else:
              ui.fatal('application class not found: {}'.format(base))
          for n, c in appcl.items():
            m = re.search(rb'^\.class .*? final .*?(L.+?;)', c)
            if m:
              ui.warn('the application class seems final, de-finalizing: {cl}'.format(cl=m.group(1).decode('utf-8', errors='replace')))
              q.patch_put(n, re.sub(rb'^(\.class .*?) final ', rb'\1 ', c), z=True)

      q.patch_put(path, self._manifest_as_xml(manif), z=True)

      path = 'smali/classes{last_block}/{pkg}/{key}.smali'.format(
        last_block=str(last_block) if last_block else '',
        pkg=pkg,
        key=key,
      )
      with as_file(files('trueseeing')/'libs'/'android') as libpath:
        env = Environment(loader=FileSystemLoader(libpath), autoescape=True, trim_blocks=True, lstrip_blocks=True)
        q.patch_put(
          path,
          env.get_template('frida-app.smali').render(
            base=self._as_dalvik_classname(base),
            cn=self._as_dalvik_classname(cn),
            lib=lib,
          ).encode('utf-8'),
          z=True
        )

    ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))

  async def _engage_tamper_inject_frida_scriptdir(self, args: deque[str]) -> None:
    await self._engage_tamper_inject_frida(args, script_dir_mode=True)

  def _as_dalvik_classname(self, jn: str) -> str:
    return 'L{};'.format(jn.replace('.', '/'))

  def _as_smali_file_pattern(self, jn: str) -> str:
    return r'^smali/classes[0-9]+/{}.smali$'.format(jn.replace('.', '/'))

  async def _prepare_frida_gadget(self, vers: str) -> Mapping[str, str]:
    import os
    from aiohttp import ClientSession
    from aiohttp.client_exceptions import ClientConnectionError
    context = self._helper.get_context()
    feedtmpl = 'https://github.com/frida/frida/releases/download/{vers}/frida-gadget-{vers}-android-{arch}.so.xz'
    pathtmpl = '{wd}/../t/frida-gadget-{vers}-android-{arch}.so.xz'
    archmap = dict(arm64='arm64-v8a', arm='armeabi-v7a', x86='x86', x86_64='x86_64')

    o = dict()

    async with ClientSession() as sess:
      for da, aa in archmap.items():
        feed = feedtmpl.format(vers=vers, arch=da)
        path = pathtmpl.format(wd=context.wd, vers=vers, arch=da)
        if not os.path.exists(path):
          ui.info(f'fetching {feed}')
          os.makedirs(os.path.dirname(path), exist_ok=True)
          try:
            async with sess.get(feed) as r:
              with open(path, 'wb') as f:
                if r.status != 200:
                  ui.warn('failed to fetch {feed}: {status}'.format(feed=feed, status=r.status))
                f.write(await r.read())
          except ClientConnectionError as e:
            ui.fatal(f'failed to fetch {feed}: {e}')
        o[aa] = path

    return o

  async def _determine_recent_frida_gadget(self) -> str:
    import re
    from aiohttp import ClientSession
    from aiohttp.client_exceptions import ClientConnectionError
    feed = 'https://frida.re/news/releases/'

    async with ClientSession() as sess:
      try:
        async with sess.get(feed) as r:
          m = re.search(r'<article>.*?frida ([0-9.]+).*</article>', await r.text(), re.DOTALL | re.IGNORECASE)
          if m:
            return m.group(1)
          else:
            raise InvalidResponseError()
      except ClientConnectionError:
        raise InvalidResponseError()

  async def _engage_device_copyout(self, args: deque[str]) -> None:
    success: bool = False

    cmd = args.popleft()
    if not args:
      ui.fatal('need package name')

    target = args.popleft()

    import os
    if not args:
      outfn = f'{target}.tar'
    else:
      outfn = args.popleft()

    outfn0 = outfn.replace('.tar', '') + '-int.tar'
    outfn1 = outfn.replace('.tar', '') + '-ext.tar'

    if os.path.exists(outfn) and not cmd.endswith('!'):
      ui.fatal('outfile exists; force (!) to overwrite')

    ui.info(f'copying out: {target} -> {outfn}')

    import time
    from shlex import quote
    from subprocess import CalledProcessError
    from trueseeing.core.tools import invoke_passthru
    from trueseeing.core.android.device import AndroidDevice
    from trueseeing.core.android.tools import toolchains

    at = time.time()
    dev = AndroidDevice()

    if not await dev.is_fullbackup_available():
      ui.warn('full backup feature is not available')
    else:
      ui.info('initiating a backup on device; give "1" as the password if asked')
      await dev.invoke_adb_passthru(f'backup -f {outfn}.ab {target}')
      try:
        try:
          with toolchains() as tc:
            await invoke_passthru('java -jar {abe} unpack {outfn}.ab {outfn} 1'.format(
              abe=tc['abe'],
              outfn=quote(outfn),
            ))
        except CalledProcessError:
          ui.warn('unpack failed (did you give the correct password?); trying the next method')
        else:
          ui.success('unpack success')
          if os.stat(outfn).st_size > 1024:
            ui.success(f'copied out: {outfn}')
            success = True
          else:
            ui.warn('got an empty backup; trying the next method')
            try:
              os.remove(outfn)
            except FileNotFoundError:
              pass
      finally:
        try:
          os.remove(f'{outfn}.ab')
        except FileNotFoundError:
          pass

    if not success:
      if not await dev.is_package_debuggable(target):
        ui.warn('target is not debuggable')
      else:
        ui.info('target seems debuggable; trying extraction with debug interface')

        tfn0 = self._generate_tempfilename_for_device()
        ui.info('copying internal storage')
        await dev.invoke_adb_passthru(f"shell 'run-as {target} tar -cv . > {tfn0}'")
        await dev.invoke_adb_passthru(f'pull {tfn0} {quote(outfn0)}')
        await dev.invoke_adb_passthru(f'shell rm -f {tfn0}')
        ui.success(f'copied out: {outfn0}')

        ui.info('copying external storage')
        tfn1 = self._generate_tempfilename_for_device()
        try:
          await dev.invoke_adb_passthru(f"shell 'cd /storage/emulated/0/Android/ && tar -cv data/{target} obb/{target} > {tfn1}'")
        except CalledProcessError:
          ui.warn('detected errors during extraction from external storage (may indicate partial extraction)')
        await dev.invoke_adb_passthru(f'pull {tfn1} {quote(outfn1)}')
        await dev.invoke_adb_passthru(f'shell rm -f {tfn1}')
        ui.success(f'copied out: {outfn1}')

        success = True

    if success:
      ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))
    else:
      ui.failure('copyout failed')

  async def _engage_device_copyin(self, args: deque[str]) -> None:
    success: bool = False

    _ = args.popleft()
    if not args:
      ui.fatal('need package name')

    target = args.popleft()

    import os
    if not args:
      fn = f'{target}.tar'
    else:
      fn = args.popleft()

    fn0 = fn.replace('.tar', '') + '-int.tar'
    fn1 = fn.replace('.tar', '') + '-ext.tar'

    if not any(os.path.exists(x) for x in [fn, fn0, fn1]):
      ui.fatal('bundle file not found')

    ui.info(f'copying in: {fn} -> {target}')

    import time
    from shlex import quote
    from subprocess import CalledProcessError
    from trueseeing.core.tools import invoke_passthru
    from trueseeing.core.android.device import AndroidDevice
    from trueseeing.core.android.tools import toolchains

    at = time.time()
    dev = AndroidDevice()

    if not await dev.is_fullbackup_available():
      ui.warn('full backup feature is not available')
    else:
      if not os.path.exists(fn):
        ui.warn(f'data not found, trying the next method: {fn}')
      else:
        try:
          try:
            with toolchains() as tc:
              await invoke_passthru('java -jar {abe} pack-kk {fn} {fn}.ab 1'.format(
                abe=tc['abe'],
                fn=quote(fn),
              ))
          except CalledProcessError:
            ui.warn('pack failed; trying the next method')
          else:
            ui.success('pack success')
            ui.info('initiating a restore on device; give "1" as the password if asked')
            await dev.invoke_adb_passthru(f'restore {quote(fn)}.ab')
            ui.success(f'copied in: {fn}')
            success = True
        finally:
          try:
            os.remove(f'{fn}.ab')
          except FileNotFoundError:
            pass

    if not success:
      if not await dev.is_package_debuggable(target):
        ui.warn('target is not debuggable')
      else:
        ui.info('target seems debuggable; trying injection with debug interface')

        ui.info('copying internal storage')
        if not os.path.exists(fn0):
          ui.warn(f'data not found: {fn0}')
        else:
          tfn0 = self._generate_tempfilename_for_device()
          await dev.invoke_adb_passthru(f'push {quote(fn0)} {tfn0}')
          await dev.invoke_adb_passthru(f"shell 'run-as {target} tar -xv < {tfn0}; rm -f {tfn0}'")
          ui.success(f'copied in: {fn}')
          success = True

        ui.info('copying external storage')
        if not os.path.exists(fn1):
          ui.warn(f'data not found: {fn1}')
        else:
          tfn1 = self._generate_tempfilename_for_device()
          await dev.invoke_adb_passthru(f'push {quote(fn1)} {tfn1}')
          await dev.invoke_adb_passthru(f"shell 'cd /storage/emulated/0/Android/ && tar -xv < {tfn1}; rm -f {tfn1}'")
          ui.success(f'copied in: {fn1}')
          success = True

        success = True

    if success:
      ui.success('done ({t:.02f} sec.)'.format(t=(time.time() - at)))
    else:
      ui.failure('copyin failed')

  async def _engage_fuzz_command(self, args: deque[str], am: bool = False) -> None:
    outfn: Optional[str] = None

    cmd = args.popleft()

    if not args:
      if am:
        ui.fatal('an "am" command line pattern required; try giving whatever you would to "adb shell am" (e.g. {} "start-activity .." ..)'.format(cmd))
      else:
        ui.fatal('command line pattern required; try giving you would to "adb shell"')

    pat = args.popleft()
    if am:
      pat = f'am {pat}'

    if args and not args[0].startswith('@'):
      import os
      outfn = args.popleft()
      if os.path.exists(outfn) and not cmd.endswith('!'):
        ui.fatal('outfile exists; force (!) to overwrite')

    wordlist: Dict[str, List[str]] = dict()
    for name, fn in self._helper.get_effective_options(self._helper.get_modifiers(args)).items():
      if name.startswith('w'):
        name = name[1:]
        try:
          with open(fn, 'r') as f:
            wordlist[name] = [x.rstrip() for x in f]
        except OSError as e:
          ui.fatal(f'cannot open wordlist: {e}')

    if not wordlist:
      ui.fatal('need a wordlist (try @o:wNAME=FN)')

    ui.info('wordlist built: {} words in {} keys ({})'.format(sum([len(v) for v in wordlist.values()]), len(wordlist), ','.join(wordlist.keys())))

    def _expand(pat: str, wordlist: Mapping[str, List[str]]) -> Iterator[Tuple[int, int, str]]:
      tries = min(len(v) for v in wordlist.values())
      for nr in range(tries):
        d = {k:v[nr] for k,v in wordlist.items()}
        try:
          yield nr, tries, pat.format(*[], **d)
        except KeyError as e:
          ui.fatal(f'unknown wordlist specified: {e}')

    ui.info('starting fuzzing, opening log system-wide{}'.format(' [{}]'.format(outfn) if outfn else ''))

    from trueseeing.core.android.device import AndroidDevice

    dev = AndroidDevice()

    async def _log(outfn: Optional[str]) -> None:
      import sys
      nr = 0

      if not outfn:
        f = sys.stdout.buffer
      else:
        f = open(outfn, 'wb')

      try:
        async for l in dev.invoke_adb_streaming('logcat -T1'):
          f.write(l)
          nr += 1
          if outfn and nr % 256 == 0:
            ui.info(' ... captured: {}')
      finally:
        if outfn:
          f.close()

    async def _fuzz(pat: str, wordlist: Mapping[str, List[str]]) -> None:
      from asyncio import sleep
      from subprocess import CalledProcessError
      for nr, tries, t in _expand(pat, wordlist):
        await sleep(.05)
        prog = dict(nr=nr+1, max=tries, cmd=t)
        try:
          await dev.invoke_adb(f'shell {t}')
          ui.info('[{nr}/{max}] {cmd}'.format(**prog))
        except CalledProcessError as e:
          ui.failure('[{nr}/{max}] {cmd}: failed: {code}'.format(code=e.returncode, **prog))

    from asyncio import create_task, wait, FIRST_COMPLETED, ALL_COMPLETED
    task_log = create_task(_log(outfn))
    task_fuzz = create_task(_fuzz(pat, wordlist))

    done, pending = await wait([task_log, task_fuzz], return_when=FIRST_COMPLETED)
    for t in pending:
      t.cancel()
    done, _ = await wait([task_log, task_fuzz], return_when=ALL_COMPLETED)
    for t in done:
      exc = t.exception()
      if exc:
        ui.error('unhandled exception', exc=exc)

  async def _engage_fuzz_intent(self, args: deque[str]) -> None:
    await self._engage_fuzz_command(args, am=True)

  async def _engage_deploy_package(self, args: deque[str]) -> None:
    cmd = args.popleft()

    context: APKContext = self._helper.get_context().require_type('apk')
    apk = context.target

    from time import time
    from shlex import quote
    from pubsub import pub
    from trueseeing.core.ui import AndroidInstallProgressReporter
    from trueseeing.core.android.device import AndroidDevice
    from subprocess import CalledProcessError

    dev = AndroidDevice()
    at = time()
    pkg = context.get_package_name()

    ui.info(f'deploying package: {pkg}')

    if cmd.endswith('!'):
      try:
        async for l in dev.invoke_adb_streaming(f'uninstall {pkg}', redir_stderr=True):
          pub.sendMessage('progress.android.adb.update')
          if b'success' in l.lower():
            ui.warn('removing existing package')
      except CalledProcessError as e:
        ui.fatal('uninstall failed: {}'.format(e.stdout.decode().rstrip()))

    with AndroidInstallProgressReporter().scoped():
      pub.sendMessage('progress.android.adb.begin', what='installing ... ')
      try:
        async for l in dev.invoke_adb_streaming(f'install --no-streaming {quote(apk)}', redir_stderr=True):
          pub.sendMessage('progress.android.adb.update')
          if b'failure' in l.lower():
            ui.stderr('')
            if not cmd.endswith('!'):
              ui.fatal('install failed; force (!) to replace ({})'.format(l.decode('UTF-8')))
            else:
              ui.fatal('install failed ({})'.format(l.decode('UTF-8')))

        pub.sendMessage('progress.android.adb.done')
      except CalledProcessError as e:
        ui.fatal('install failed: {}'.format(e.stdout.decode().rstrip()))

      ui.success('done ({t:.02f} sec){trailer}'.format(t=time() - at, trailer=' '*8))

  async def _engage_undeploy_package(self, args: deque[str]) -> None:
    _ = args.popleft()

    context: APKContext = self._helper.get_context().require_type('apk')

    from time import time
    from pubsub import pub
    from trueseeing.core.android.device import AndroidDevice
    from subprocess import CalledProcessError

    dev = AndroidDevice()
    at = time()
    pkg = context.get_package_name()

    ui.info(f'removing package: {pkg}')

    try:
      async for l in dev.invoke_adb_streaming(f'uninstall {pkg}', redir_stderr=True):
        pub.sendMessage('progress.android.adb.update')
        if b'failure' in l.lower():
          import re
          packages = await dev.invoke_adb('shell pm list packages', redir_stderr=True)
          if not re.match(f'{pkg}$', packages, re.MULTILINE):
            ui.fatal('package not found')
          else:
            ui.fatal('uninstall failed ({})'.format(l.decode()))
    except CalledProcessError as e:
      ui.fatal('uninstall failed: {}'.format(e.stdout.decode().rstrip()))

    ui.success('done ({t:.02f} sec)'.format(t=time() - at))

  async def _engage_grab_package(self, args: deque[str]) -> None:
    cmd = args.popleft()

    import os
    if not args:
      ui.fatal('need the package name')

    pkg = args.popleft()

    if args:
      outfn = args.popleft()
    else:
      outfn = f'{pkg}.apk'

    if os.path.exists(outfn):
      if not cmd.endswith('!'):
        ui.fatal('output file exists; force (!) to overwrite')
      else:
        os.remove(outfn)

    import re
    from time import time
    from tempfile import TemporaryDirectory
    from pubsub import pub
    from trueseeing.core.android.device import AndroidDevice

    dev = AndroidDevice()
    at = time()
    outfn = os.path.realpath(outfn)

    ui.info(f'grabbing package: {pkg} -> {outfn}')

    basepath: Optional[bytes] = None
    splits: List[bytes] = []

    async for l in dev.invoke_adb_streaming(f'shell pm dump {pkg}', redir_stderr=True):
      pub.sendMessage('progress.android.adb.update')
      if f'unable to find package: {pkg}'.encode() in l.lower():
        ui.fatal(f'package not found: {pkg}')

      m = re.search(rb'codePath=(/.+)', l)
      if m:
        basepath = m.group(1)
      m = re.search(rb'splits=\[(.+)\]', l)
      if m:
        splits = re.split(rb', *', m.group(1))

    assert basepath
    assert splits

    with TemporaryDirectory() as td:
      from os import chdir, getcwd
      from shlex import quote
      from zipfile import ZipFile, ZIP_STORED
      cd = getcwd()
      try:
        chdir(td)
        slicemap = dict()
        if len(splits) == 1:
          if outfn.endswith('.xapk'):
            ui.warn('target has only one slice; using apk format')
            outfn = outfn.replace('.xapk', '.apk')
          ui.info('getting {nr} slice'.format(nr=len(splits)))
          await dev.invoke_adb('pull {path}/base.apk {outfn}'.format(path=quote(basepath.decode()), outfn=quote(outfn)))
        else:
          if outfn.endswith('.apk'):
            ui.warn('target has multiple slices; using xapk format')
            outfn = outfn.replace('.apk', '.xapk')
          ui.info('getting {nr} slices'.format(nr=len(splits)))
          for s in splits:
            slice = s.decode()
            if slice == 'base':
              fn = f'{pkg}.apk'
            else:
              fn = f'{slice}.apk'
            await dev.invoke_adb('pull {path}/{typ}{slice}.apk {fn}'.format(
              path=quote(basepath.decode()),
              typ='' if slice == 'base' else 'split_',
              slice=slice,
              fn=fn,
            ))
            slicemap[slice] = fn
          XAPKManifestGenerator(slicemap).generate()
          with ZipFile(outfn, 'w', ZIP_STORED) as zf:
            from glob import glob
            for n in glob('*'):
              with open(n, 'rb') as g:
                zf.writestr(n, g.read())
      finally:
        chdir(cd)
    ui.success('done ({t:.02f} sec)'.format(t=time() - at))

  def _generate_tempfilename_for_device(self, dir: Optional[str] = None) -> str:
    import random
    return (f'{dir}/' if dir is not None else '/data/local/tmp/') + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))

  def _parsed_manifest(self, blob: bytes) -> Any:
    import lxml.etree as ET
    return ET.fromstring(blob, parser=ET.XMLParser(recover=True))

  def _manifest_as_xml(self, manifest: Any) -> bytes:
    import lxml.etree as ET
    assert manifest is not None
    return ET.tostring(manifest) # type: ignore[no-any-return]

  async def _engage_frida_start_server(self, args: deque[str]) -> None:
    cmd = args.popleft()
    context: APKContext = self._helper.get_context().require_type('apk')

    pkg = context.get_package_name()
    scripts = list(args)

    force = cmd.endswith('!')

    ui.info("starting frida-server")

    from time import time
    from shlex import quote
    from trueseeing.core.android.device import AndroidDevice
    from trueseeing.core.tools import invoke_passthru
    from pathlib import Path

    at = time()
    dev = AndroidDevice()

    if force:
      ui.warn("killing frida-server if any")
      await dev.invoke_adb("shell 'killall frida-server || exit 0'")
    await dev.invoke_adb("shell 'cd /data/local/tmp && ./frida-server &'")

    ui.info(f"starting frida on {pkg}")
    scripts_str = []
    for s in scripts:
      p = Path(s)
      if p.is_file():
        scripts_str.append(f"-l {quote(str(p))}")
      elif p.is_dir():
        scripts_str.extend([f"-l {quote(str(m))}" for m in p.rglob('*.js')])
      else:
        ui.warn(f"ignoring unknown path: {p}")
    await invoke_passthru(f"frida -U {pkg} {' '.join(scripts_str)}")

    ui.success("done ({t:.2f} sec.)".format(t=time() - at))

  async def _engage_frida_kill_server(self, args: deque[str]) -> None:
    from time import time
    from trueseeing.core.android.device import AndroidDevice

    ui.info("killing frida-server")

    at = time()
    dev = AndroidDevice()

    await dev.invoke_adb('shell killall frida-server')

    ui.success("done ({t:.2f} sec.)".format(t=time() - at))

class InvalidResponseError(Exception):
  pass

class XAPKManifestGenerator:
  def __init__(self, slicemap: Dict[str, str]) -> None:
    self._slicemap = slicemap

  def generate(self) -> None:
    from os import stat
    from pyaxmlparser import APK
    manif: XAPKManifest = dict(
      xapk_version='2',
      total_size=0,
      locales_name=dict(),
      split_apks=[],
    )

    for slice, fn in self._slicemap.items():
      conf = slice.split('.')[-1]
      manif['total_size'] += stat(fn).st_size
      manif['split_apks'].append(dict(id=slice, file=fn))
      if slice == 'base':
        apk = APK(fn)
        manif.update(dict(
          name=apk.get_app_name(),
          icon='icon.png',
          package_name=apk.get_package(),
          version_code=apk.version_code,
          version_name=apk.version_name,
          min_sdk_version=apk.get_min_sdk_version(),
          target_sdk_version=apk.get_target_sdk_version(),
          permissions=apk.get_permissions(),
        ))
        with open('icon.png', 'wb') as f:
          f.write(apk.icon_data)
      elif len(conf) == 2:
        apk = APK(fn)
        country_code = conf
        manif['locales_name'].update({
          country_code:apk.get_app_name(),
        })
      if manif['locales_name']:
        ln: Dict[str, str] = manif['locales_name']
        for k in ln.keys():
          if not ln[k]:
            ln[k] = manif['name']
    with open('manifest.json', 'w') as g:
      from json import dumps
      g.write(dumps(manif, separators=(',', ':')))
