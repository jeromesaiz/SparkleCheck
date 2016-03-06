#!/usr/bin/env python

__description__ = 'Script to search for Mac applications vulnerable to Sparkle.framework MITM attacks'
__see__ = 'https://vulnsec.com/2016/osx-apps-vulnerabilities/'
__author__ = 'Jerome Saiz (http://go16.fr)'
__version__ = '0.0.1'
__date__ = '2016/03/06'

"""

Source code put in public domain by Jerome Saiz, no copyright
Use at your own risk !

Credits:
- https://macmule.com/ for the Mac-specific app discovery command

History:
  2016/03/06: initial commit

"""

import os
import sys
import glob
import plistlib
import subprocess
import platform
from urlparse import urlparse
try:
  import biplist
  nobiplist = False
except:
  nobiplist = True

# Coloring definition
INFO = '\033[94m'
OK = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'

AppPlist = '/Contents/Info.plist'
SparklePlist = '/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Info.plist'

# Quick check for platform (Mac-only)
if platform.system() != 'Darwin':
  print '\n' + FAIL + 'ERROR :' + ENDC + ' Are you sure we\'re on a Mac ? ;)'
  sys.exit(1)

# Get all registered apps
apps = subprocess.check_output(['/usr/bin/mdfind', 'kind:app'])

print '\n## SparkleCheck ##\n\nChecking Mac applications for vulnerable Sparkle Framework installs\n(see https://vulnsec.com/2016/osx-apps-vulnerabilities/)\n'

print 'Usage : This script lists your applications embeding the Sparkle.framework.\nSparkle versions before 1.13.1 may be vulnerable if they update through HTTP instead of the more secure HTTPS protocol.\nPlease consider using/updating those through a secure VPN connexion first.\n'

# biplist allows to read binary plist files used by some applications
# see https://pypi.python.org/pypi/biplist/1.0.1
if nobiplist:
  print WARNING + 'NOTE : biplist library not installed : I might not be able to report on all applications \nConsider running pip install biplist\n' + ENDC
else:
  print "NOTE : biplist library installed. That's good :)\n"

# Let's go : iterate through /Applications/
for app in apps.splitlines():

  # Look for Sparkle.framework plist file
  fullSparkelPath = app+SparklePlist

  if os.path.isfile(fullSparkelPath):
    pl = plistlib.readPlist(fullSparkelPath)

    # Try to detect Sparkle Version
    try:
      sparkleVersion = INFO + pl['CFBundleShortVersionString'] + ENDC
    except:
      try:
        sparkleVersion = INFO + pl['CFBundleVersion'] + '(Build version only)' + ENDC
      except:
        sparkleVersion = WARNING + '??' + ENDC

    # Version numbering is too unpredictable.
    # No safe way to decide automagically if version is vulnerable
    # (distutils.version or pkg_resources.parse_version do not seem reliable enough)
    # So we'll just display the version number extracted from the plist and let the user be judge

    # Look for App plist file
    fullAppPlist = app+AppPlist

    if os.path.isfile(fullAppPlist):
      try:
        apl = plistlib.readPlist(fullAppPlist)
      except:
        try:
          apl = biplist.readPlist(fullAppPlist)
        except:
          apl = False

    # Get app pretty name & version
    # Name
    if apl:
      try:
        appName = apl['BundleDisplayName']
      except:
        try:
          appName = apl['CFBundleName']
        except:
          try:
            appName = apl['CFBundleExecutable']
          except:
            appName = app

      # Version
      try:
        appVersion = apl['CFBundleShortVersionString']
      except:
        try:
          appVersion = apl['CFBundleVersion']
        except:
          appVersion = ''

    else:
      appName = app

    # Try to detect update URL & extract protocol
    try:
     updateURL = apl['SUFeedURL']
     proto = urlparse(updateURL).scheme

     if proto == 'https':
      proto = OK + 'https' + ENDC
     else:
      proto = FAIL + 'http' + ENDC

    except:
      proto = WARNING + '??'
      if nobiplist:
        proto = proto + ' (try installing biplist)'
      else:
        proto = proto + ' (no Sparkle.framework update URL found)'
      proto = proto+ENDC

    # Display result line
    print '## ' + INFO + appName + ' ' + appVersion + ENDC +  ' has Sparkle version '  + sparkleVersion + ' and updates via ' + proto

# exit with no errors
sys.exit(0)
