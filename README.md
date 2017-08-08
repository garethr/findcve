FindCVE is a proof-of-concept, originally written for a talk at [CamSec](https://www.meetup.com/Camsec/).
It works as shown  below but currently lacks sane error handling and currently only works with Debian distros.

## Usage

```
$ findcve
Usage: findcve [OPTIONS] COMMAND [ARGS]...

  FindCVE scans different file formats for lists of packages and the
  operating system version and looks up any known CVEs from the relevant
  source

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  inventory  Inventory scans the output from puppet...
  lumogon    Lumogon scans the output from the lumogon...
  puppet     Puppet scans the output from puppet resource
```

## Inventory

[Puppet Inventory](https://github.com/puppetlabs/puppetlabs-inventory) is a module which adds an inventory subcommand which acts a bit like an all-in-one version of `puppet resource`. It outputs both package and fact data so we can do:

```
$ puppet inventory | findcve inventory
apt has vulnerabilities
   Currently installed 1.0.9.8.4
   Latest version 1.0.9.8.4
   CVE-2011-3374 is unimportant
bash has vulnerabilities
   Currently installed 4.3-11+deb8u1
   Latest version 4.3-11+deb8u1
   TEMP-0841856-B18BAF is unimportant
   CVE-2016-9401 is low**
coreutils has vulnerabilities
   Currently installed 8.23-4
   Latest version 8.23-4
   CVE-2016-2781 is low**
dpkg has vulnerabilities
   Currently installed 1.17.27
   Latest version 1.17.27
   CVE-2017-8283 is unimportant
gnupg has vulnerabilities
   Currently installed 1.4.18-7+deb8u3
   Latest version 1.4.18-7+deb8u3
   CVE-2017-7526 is not yet assigned
libgcrypt20 has vulnerabilities
   Currently installed 1.6.3-2+deb8u4
   Latest version 1.6.3-2+deb8u4
   TEMP-0000000-96B2E9 is not yet assigned
libtasn1-6 has vulnerabilities
   Currently installed 4.2-3+deb8u3
   Latest version 4.2-3+deb8u3
   CVE-2017-10790 is medium**
openssl has vulnerabilities
   Currently installed 1.0.1t-1+deb8u6
   Latest version 1.0.1t-1+deb8u6
   CVE-2010-0928 is unimportant
   CVE-2007-6755 is unimportant
systemd has vulnerabilities
   Currently installed 215-17+deb8u7
   Latest version 215-17+deb8u7
   CVE-2013-4392 is unimportant
tar has vulnerabilities
   Currently installed 1.27.1-2+deb8u1
   Latest version 1.27.1-2+deb8u1
   TEMP-0290435-0B57B5 is unimportant
   CVE-2005-2541 is unimportant
util-linux has vulnerabilities
   Currently installed 2.25.2-6
   Latest version 2.25.2-6
   CVE-2016-2779 is high**
   CVE-2015-5218 is unimportant
   CVE-2015-5224 is unimportant
   TEMP-0786804-C23D2B is unimportant
   CVE-2016-5011 is medium**
   CVE-2017-2616 is unimportant
wget has vulnerabilities
   Currently installed 1.16-1+deb8u2
   Latest version 1.16-1+deb8u2
   CVE-2016-7098 is low
 ```

## Lumogon

Lumogon contains both the list of packages with versions, and the OS details. So we can pipe it to findcve using the lumogon subcommand:

```
$ docker run --rm  -v /var/run/docker.sock:/var/run/docker.sock puppet/lumogon scan | findcve lumogon
```

The output will show a list of vulnerabilities for each detected container:

```
==> Scanning /peaceful_goldberg
apt has vulnerabilities
   Currently installed 1.0.9.8.4
   Latest version 1.0.9.8.4
   CVE-2011-3374 is unimportant
bash has vulnerabilities
   Currently installed 4.3-11+deb8u1
   Latest version 4.3-11+deb8u1
   CVE-2016-9401 is low**
   TEMP-0841856-B18BAF is unimportant
coreutils has vulnerabilities
   Currently installed 8.23-4
   Latest version 8.23-4
   CVE-2016-2781 is low**
dpkg has vulnerabilities
   Currently installed 1.17.27
   Latest version 1.17.27
   CVE-2017-8283 is unimportant
gnupg has vulnerabilities
   Currently installed 1.4.18-7+deb8u3
   Latest version 1.4.18-7+deb8u3
   CVE-2017-7526 is not yet assigned
libgcrypt20 has vulnerabilities
   Currently installed 1.6.3-2+deb8u4
   Latest version 1.6.3-2+deb8u4
   TEMP-0000000-96B2E9 is not yet assigned
libtasn1-6 has vulnerabilities
   Currently installed 4.2-3+deb8u3
   Latest version 4.2-3+deb8u3
   CVE-2017-10790 is medium**
openssl has vulnerabilities
   Currently installed 1.0.1t-1+deb8u6
   Latest version 1.0.1t-1+deb8u6
   CVE-2010-0928 is unimportant
   CVE-2007-6755 is unimportant
systemd has vulnerabilities
   Currently installed 215-17+deb8u7
   Latest version 215-17+deb8u7
   CVE-2013-4392 is unimportant
tar has vulnerabilities
   Currently installed 1.27.1-2+deb8u1
   Latest version 1.27.1-2+deb8u1
   CVE-2005-2541 is unimportant
   TEMP-0290435-0B57B5 is unimportant
util-linux has vulnerabilities
   Currently installed 2.25.2-6
   Latest version 2.25.2-6
   TEMP-0786804-C23D2B is unimportant
   CVE-2016-2779 is high**
   CVE-2017-2616 is unimportant
   CVE-2015-5218 is unimportant
   CVE-2015-5224 is unimportant
   CVE-2016-5011 is medium**
wget has vulnerabilities
   Currently installed 1.16-1+deb8u2
   Latest version 1.16-1+deb8u2
   CVE-2016-7098 is low
 ```

## Puppet

We can also just use the direct output from `puppet resource` which gives us the packages and versions.
We need the `--param provider` part to find only `apt` packages and we also need to specify the os.

```
$ puppet resource package --param provider | findcve puppet --os jessie
apt has vulnerabilities
   Currently installed 1.0.9.8.4
   Latest version 1.0.9.8.4
   CVE-2011-3374 is unimportant
bash has vulnerabilities
   Currently installed 4.3-11+deb8u1
   Latest version 4.3-11+deb8u1
   TEMP-0841856-B18BAF is unimportant
   CVE-2016-9401 is low**
coreutils has vulnerabilities
   Currently installed 8.23-4
   Latest version 8.23-4
   CVE-2016-2781 is low**
dpkg has vulnerabilities
   Currently installed 1.17.27
   Latest version 1.17.27
   CVE-2017-8283 is unimportant
gnupg has vulnerabilities
   Currently installed 1.4.18-7+deb8u3
   Latest version 1.4.18-7+deb8u3
   CVE-2017-7526 is not yet assigned
libgcrypt20 has vulnerabilities
   Currently installed 1.6.3-2+deb8u4
   Latest version 1.6.3-2+deb8u4
   TEMP-0000000-96B2E9 is not yet assigned
libtasn1-6 has vulnerabilities
   Currently installed 4.2-3+deb8u3
   Latest version 4.2-3+deb8u3
   CVE-2017-10790 is medium**
openssl has vulnerabilities
   Currently installed 1.0.1t-1+deb8u6
   Latest version 1.0.1t-1+deb8u6
   CVE-2007-6755 is unimportant
   CVE-2010-0928 is unimportant
systemd has vulnerabilities
   Currently installed 215-17+deb8u7
   Latest version 215-17+deb8u7
   CVE-2013-4392 is unimportant
tar has vulnerabilities
   Currently installed 1.27.1-2+deb8u1
   Latest version 1.27.1-2+deb8u1
   TEMP-0290435-0B57B5 is unimportant
   CVE-2005-2541 is unimportant
util-linux has vulnerabilities
   Currently installed 2.25.2-6
   Latest version 2.25.2-6
   CVE-2017-2616 is unimportant
   CVE-2016-2779 is high**
   TEMP-0786804-C23D2B is unimportant
   CVE-2015-5224 is unimportant
   CVE-2015-5218 is unimportant
   CVE-2016-5011 is medium**
wget has vulnerabilities
   Currently installed 1.16-1+deb8u2
   Latest version 1.16-1+deb8u2
   CVE-2016-7098 is low
 ```
