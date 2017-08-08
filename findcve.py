from collections import defaultdict
import fileinput
import json
import math
from pathlib import Path
import sys

import click
from version_utils import rpm
import yaml
import requests
from clint.textui import progress


COLOR_MAPPING = {
    "not yet assigned": "white",
    "unimportant": "white",
    "low": "white",
    "medium": "yellow",
    "high": "red",
}

DEBIAN_CODENAMES = {
    7: "wheezy",
    8: "jessie",
    9: "stretch",
    10: "buster",
    "unstable": "sid"
}

# https://stackoverflow.com/questions/39359390/how-to-use-yaml-load-all-with-fileinput-input
class MinimalAdapter:
    def __init__(self):
        self._fip = None
        self._buf = None  # storage of read but unused material, maximum one line

    def __call__(self, fip):
        self._fip = fip  # store for future use
        self._buf = ""
        return self

    def read(self, size):
        if len(self._buf) >= size:
            # enough in buffer from last read, just cut it off and return
            tmp, self._buf = self._buf[:size], self._buf[size:]
            return tmp
        for line in self._fip:
            self._buf += line
            if len(self._buf) > size:
                break
        else:
            # ran out of lines, return what we have
            tmp, self._buf = self._buf, ''
            return tmp
        tmp, self._buf = self._buf[:size], self._buf[size:]
        return tmp


def determine_cves(package, version, os, cve_data):
    vulnerabilities = []
    if package in cve_data:
        cves = cve_data[package]

        for cve in cves:
            if os in cves[cve]["releases"].keys():
                urgency = cves[cve]["releases"][os]["urgency"]
                if "fixed_version" in cves[cve]["releases"][os]:
                    fixed = cves[cve]["releases"][os]["fixed_version"]
                    vulnerable = rpm.compare_versions(fixed, version) > 0
                else:
                    fixed = False
                    vulnerable = True
                if vulnerable:
                    latest = cves[cve]["releases"][os]["repositories"][os]
                    vulnerability = {
                        "cve": cve,
                        "urgency": urgency,
                        "fixed": fixed,
                        "installed": version,
                        "latest": latest,
                    }
                    vulnerabilities.append(vulnerability)
    return vulnerabilities

def load_data(file):
    if not sys.stdin.isatty():
        file = "-" 
    adapter = MinimalAdapter()
    return yaml.safe_load(adapter(fileinput.input(file)))

def load_vulnerability_database():
    # Currently manually downloaded from
    # https://security-tracker.debian.org/tracker/data/json
    # Should instead download if not found in option localtion
    # or redownload if found but out of date
    # progress bar for download
    
    url = "https://security-tracker.debian.org/tracker/data/json"
    db = Path('debian.json')
    r = requests.get(url, stream=True)
    if not db.exists():
        with open(db.name, 'wb') as data_file:
            total_length = 1024*20722
            for chunk in progress.bar(r.iter_content(chunk_size=1024), label="Downloading Debian data", expected_size=(total_length/1024) + 1): 
                if chunk:
                    data_file.write(chunk)
                    data_file.flush()
    with open(db.name, 'r') as data_file:
        return json.load(data_file)

def print_vulns(package, vulns):
    if vulns:
        click.secho("%s has vulnerabilities" % package, fg="green")
        click.echo("   Currently installed %s" % vulns[0]["installed"])
        click.echo("   Latest version %s" % vulns[0]["latest"])
        for vuln in vulns:
            click.echo("   %s is %s" % (vuln["cve"], click.style(vuln["urgency"], fg=COLOR_MAPPING[vuln["urgency"].replace("*", "")])))
            if vuln["fixed"]:
                click.echo("      Vulnerability fixed in %s" % vuln["fixed"])

@click.group()
@click.version_option("0.1.0")
def cli():
    """
    FindCVE scans different file formats for lists of packages
    and the operating system version and looks up any
    known CVEs from the relevant source
    """
    pass

@cli.command()
@click.option("--file", default="inventory.json")
def inventory(file):
    """
    Inventory scans the output from puppet inventory.
    This output requires the puppetlabs-inventory
    module to be installed
    """
    cve_data = load_vulnerability_database()
    inventory = load_data(file)
    os = DEBIAN_CODENAMES[float(inventory["facts"]["operatingsystemmajrelease"])]
    resources = inventory["resources"]
    packages = [item for item in resources if item["resource"] == "package" and item["provider"] == "apt"]
    for package in packages:
        version = package["versions"][0]
        title = package["title"]
        vulns = determine_cves(title, version, os, cve_data)
        print_vulns(title, vulns)


@cli.command()
@click.option("--file", default="lumogon.json")
def lumogon(file):
    """
    Lumogon scans the output from the lumogon container
    inspection tool
    """
    cve_data = load_vulnerability_database()
    containers = load_data(file)["containers"]
    for container in containers:
        click.secho("==> Scanning %s" % containers[container]["container_name"], fg="blue")
        packages = containers[container]["capabilities"]["dpkg"]["payload"]
        host = containers[container]["capabilities"]["host"]["payload"]
        os = DEBIAN_CODENAMES[math.floor(float(host["platformversion"]))]
        for package in sorted(packages):
            version = packages[package]
            vulns = determine_cves(package, version, os, cve_data)
            print_vulns(package, vulns)


@cli.command()
@click.option("--os", default="jessie", type=click.Choice(DEBIAN_CODENAMES.values()), help="Debian OS codename")
@click.option("--file", default="packages.yaml")
def puppet(os, file):
    """
    Puppet scans the output from puppet resource
    """

    cve_data = load_vulnerability_database()
    contents = load_data(file)
    packages = contents["package"]

    for package in sorted(packages):
        if packages[package]["provider"] == "apt":
            version = packages[package]["ensure"]
            vulns = determine_cves(package, version, os, cve_data)
            print_vulns(package, vulns)

if __name__ == '__main__':
    cli(auto_envvar_prefix='FINDCVE')
