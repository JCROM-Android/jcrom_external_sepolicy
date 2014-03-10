#!/usr/bin/env python

"""
Multifunctional tool to help build, parse and modify mac_permissions.xml
policy files. Supported operations include the following:

  modify) ability to modify an existing mac_permissions.xml with additional
  app certs not already found in policy. This becomes useful when a directory
  containing apps is searched and public certs absent from an existing
  mac_permissions.xml file are added from each app.

  build) ability to help create valid signature stanzas to be inserted into
  a mac_permissions.xml file. This will output a signer stanza with a
  package name and seinfo tag for each public cert found.
"""

import sys
import os
import argparse
from base64 import b16encode, b64decode
import fileinput
import re
import subprocess
import zipfile


PEM_CERT_RE = """-----BEGIN CERTIFICATE-----
(.+?)
-----END CERTIFICATE-----
"""
def parse_der(der_data):
  """Parse a DER encoded data stream.

  Extract all the contained public certs returning them as
  a list of lowercase hex encoded strings. An exception
  will be raised if the openssl call to fetch the certs
  fails or if the attempt to decode the base64 certs fail."""

  cmd = ['openssl', 'pkcs7', '-inform', 'DER',
         '-outform', 'PEM', '-print_certs']
  p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  pem_string, err = p.communicate(der_data)
  if err and err.strip():
      raise RuntimeError(err)

  # turn multiline base64 to single line base16
  transform = lambda x: b16encode(b64decode(x.replace('\n', ''))).lower()
  results = re.findall(PEM_CERT_RE, pem_string, re.DOTALL)

  return [transform(i) for i in results]


def collect_cert_for_app(filename):
  """Collect public certs for a specified apk.

  Returns a set containing all the public certs found for
  the provided app. The certs will be lowercase hex encoded
  strings. An exception will be raised if the openssl
  call fails or the attempt to decode the base64 certs fail."""

  app_certs = set()
  try :
    with zipfile.ZipFile(filename, 'r') as apkzip:
      for info in apkzip.infolist():
        name = info.filename
        if name.startswith('META-INF/') and name.endswith(('.DSA', '.RSA')):
          certs = parse_der(apkzip.read(name))
          app_certs.update(certs)
  except Exception as e:
    # rethrow so we can add the app involved
    raise type(e)('Encountered error with %s (%s)' % (filename, e))

  return app_certs


def collect_all_certs(dirlist):
  """Collect public certs for all apks found in a directory.

  Extract all the contained public certs from all apks found
  in dirlist. A recursive walk of the supplied directory will
  be performed and a set of all public certs found will be
  returned. Each cert will be a lowercase hex encoded string."""

  all_apps = collect_all_apks(dirlist)

  all_app_certs = set()
  for app in all_apps:
    app_certs = collect_cert_for_app(app)
    all_app_certs.update(app_certs)

  return all_app_certs


def collect_all_apks(dirlist):
  """Find all apks under a specified directory.

  A recursive walk of the supplied directory will be performed
  and a list containing the apps, including their paths, will
  be returned.
  """

  all_apps = []
  for dirpath, _, files in os.walk(dirlist):
    transform = lambda x: os.path.join(dirpath, x)
    condition = lambda x: x.endswith('.apk')
    apps = [transform(i) for i in files if condition(i)]
    all_apps.extend(apps)

  return all_apps


def build_signature_stanzas(certs, seinfo, spacing=False, pkgName=None):
  """Build a mac_permissions.xml stanza for all certs.

  Returns a list where each element represents a valid signature
  stanza, along with an attached seinfo tag and optional package name
  tag, which is capable of being included in a mac_permissions.xml policy
  file. Each stanza, by default, will not include spacing between tags
  unless spacing is set to True. If pkgName is specified then the package
  tag will be created for each signature stanza."""

  lf = ('', '\n')[spacing]
  tab = ('', '\t')[spacing]

  inner_tag = '<seinfo value="%s"/>' % seinfo
  if pkgName:
    inner_tag = '<package name="%s">%s%s%s%s%s</package>' % (pkgName, lf, tab*2,
                                                             inner_tag, lf, tab)

  stanza = '<signer signature="%s">%s%s%s%s</signer>'
  return [stanza % (cert, lf, tab, inner_tag, lf) for cert in certs]


def name_from_manifest(app):
  """Return the package name associated with an app.

  A string representing the package name of the app will
  be returned or None if not found.
  """

  p = subprocess.Popen(["aapt", "dump", "xmltree", app,
                        "AndroidManifest.xml"],
                       stdout=subprocess.PIPE)
  manifest, err = p.communicate()
  if err:
    raise RuntimeError('Problem running aapt on %s (%s).' % (app, err))

  package_name = None
  for line in manifest.split("\n"):
    line = line.strip()
    m = re.search('A: (\S*?)(?:\(0x[0-9a-f]+\))?="(.*?)" \(Raw', line)
    if m:
      name = m.group(1)
      if name == "package":
        package_name = m.group(2)
        break

  return package_name


def dump_stanzas(args):
  """Dump mac_perms signature stanzas from apps in a directory to stdout.

  Create a signature stanza for all public certs that are found
  for all apps in a specified directory. Each signature stanza will
  include the package name of the app along with the seinfo tag."""

  for app in collect_all_apks(args.dir):
    app_certs = collect_cert_for_app(app)
    name = name_from_manifest(app)
    stanzas = build_signature_stanzas(app_certs, args.seinfo, spacing=True,
                                      pkgName=name)
    print ''.join(stanzas)


def add_leftover_certs(args):
  """Build mac_permissions.xml stanzas for newly found certs.

  Appends to an existing mac_permissions.xml file policy stanzas
  for all certs found in apks from dirlist not already found in
  policy. Included in each stanza is the seinfo string."""

  app_certs = collect_all_certs(args.dir)
  if app_certs:
    policy_certs = set()
    with open(args.policy, 'r') as f:
      cert_pattern = 'signature="([a-fA-F0-9]+)"'
      policy_certs = re.findall(cert_pattern, f.read())

    cert_diff = app_certs.difference(policy_certs)
    new_stanzas = build_signature_stanzas(cert_diff, args.seinfo)
    mac_perms_string = ''.join(new_stanzas)
    mac_perms_string += '</policy>'
    for line in fileinput.input(args.policy, inplace=True):
      print line.replace('</policy>', mac_perms_string)


def main(argv):
  parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                   description=__doc__)
  parser_shared = argparse.ArgumentParser(add_help=False)

  # sub process shared arguments
  parser_shared.add_argument('-d', '--dir', dest='dir', required=True,
                             help='Directory to search for apks')

  parser_shared.add_argument('-s', '--seinfo', dest='seinfo', required=True,
                             help='seinfo tag for each generated stanza')

  sub_parsers = parser.add_subparsers(help='sub-command help')

  # modify sub process, mod an exisitng mac_perms file with new certs
  modify = sub_parsers.add_parser('modify', help='modify -h',
                                  parents=[parser_shared])

  modify.add_argument('-f', '--file', dest='policy', required=True,
                      help='mac_permissions.xml policy file')

  modify.set_defaults(func=add_leftover_certs)

  # build sub process, dump all signature stanzas for apps
  build = sub_parsers.add_parser('build', help='build -h',
                                 parents=[parser_shared])

  build.set_defaults(func=dump_stanzas)

  args = parser.parse_args()
  args.func(args)


if __name__ == '__main__':
  main(sys.argv)
