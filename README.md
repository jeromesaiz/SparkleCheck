# SparkleCheck
Python script to check for vulnerable Sparkle.framework enabled OSX applications.

One month after the Sparkle.framework MitM vulnerabilty I needed a quick & dirty way to check which of my OSX applications had been safely updated. Following the good old principle of RtWBIC (Reinventing the Wheel Because I can) I wrote this Python script.

## Usage
This is Python. Just run `python SparkleCheck.py` (the srcipt is env-enabled) or `chmod +x ./SparkleCheck.py` and `./SparkleCheck.py`.
The script will dump all your registered applications and will show you only those embedding the Sparkle framework, as well as its version and their update protocol (HTTP or HTTPS).

## What applications are vulnerable ?
Applications running Sparkle prior version _1.13.1_ *AND* using unsecured HTTPS protocol for updates are at risk.
To be compromised they would need to be updated over an insecure connexion (such as public WiFi) with an attacker prowling and ready to perform a Man-in-the-Middle attack.
See https://vulnsec.com/2016/osx-apps-vulnerabilities/ for more information.

## Limitations
Applications embeding Sparkle are free to customize how they display its version. So you are likely to find all kind of very different string version formats like _1.10.0 git-c08c15d_, _1.5 Beta (bzr)_ or even _1.5 (appname)_. This does make automatic version comparison difficult with traditionnal Python libraries such as distutils.version or pkg_resources.parse_version. So this script will only show the version number.
But it does it with pretty colors and nicely formatted :)
