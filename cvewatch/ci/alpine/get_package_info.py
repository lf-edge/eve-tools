# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Extract package metadata from Alpine Linux APKBUILD files.
# Parses package information including versions, maintainers, security fixes,
# and generates CPE identifiers for vulnerability scanning.

import os
import re
import json
import sys
import subprocess
import gzip
import xml.etree.ElementTree as ET

CVE_PATTERN = re.compile(r'cve-\d{4}-\d{4,}')
MAINTAINER_PATTERN = re.compile(r'^# Maintainer:\s*([^<]+)\s*<', re.MULTILINE)

# Global CPE mapping cache
CPE_MAPPING = None

def source_apkbuild(apkbuild_path, var_names):
    if not os.path.exists(apkbuild_path):
        return {var: None for var in var_names}

    # dir and file name
    apkbuild_dir = os.path.dirname(os.path.abspath(apkbuild_path))
    apkbuild_file = os.path.basename(apkbuild_path)

    var_prints = "\n".join([f'echo "__VAR_START__{var}__VAR_SEP__$(eval echo \\"${{{var}}}\\")"' for var in var_names])
    shell_cmd = f'''
    set +e
    cd "{apkbuild_dir}"
    # define dummy functions that might be called in APKBUILDs
    die() {{ return 0; }}
    msg() {{ return 0; }}
    warning() {{ return 0; }}
    error() {{ return 0; }}
    . "./{apkbuild_file}" 2>/dev/null
    {var_prints}
    '''

    try:
        shell_path = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
        result = subprocess.run(
            [shell_path, '-c', shell_cmd],
            capture_output=True,
            text=True,
            timeout=5,
            env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        )

        variables = {}
        for line in result.stdout.split('\n'):
            if '__VAR_START__' in line:
                parts = line.split('__VAR_SEP__', 1)
                if len(parts) == 2:
                    var_name = parts[0].replace('__VAR_START__', '')
                    var_value = parts[1].strip()
                    variables[var_name] = var_value if var_value else None

        for var in var_names:
            if var not in variables:
                variables[var] = None
        return variables

    except subprocess.TimeoutExpired:
        print(f"Warning: Timeout sourcing {apkbuild_path}")
        return {var: None for var in var_names}
    except Exception as e:
        print(f"Warning: Error sourcing {apkbuild_path}: {e}")
        return {var: None for var in var_names}

def get_all_secfixes(file_content, extra):
    content = file_content.lower()
    cve_pattern = r'cve-\d{4}-\d{4,}'
    cve_matches = re.findall(cve_pattern, content)
    cve_matches.extend(extra)
    return list(set(cve_matches))

def extract_maintainer(file_content):
    match = MAINTAINER_PATTERN.search(file_content)
    if match:
        return match.group(1).strip()
    return None

def load_cpe_dictionary(cpe_dict_path):
    global CPE_MAPPING

    if CPE_MAPPING is not None:
        return CPE_MAPPING

    CPE_MAPPING = {}
    if not cpe_dict_path or not os.path.exists(cpe_dict_path):
        print("Warning: CPE dictionary not found, vendor lookup will be limited", file=sys.stderr)
        return CPE_MAPPING

    try:
        print("Loading CPE dictionary...", file=sys.stderr)
        with gzip.open(cpe_dict_path, 'rt', encoding='utf-8') as f:
            for event, elem in ET.iterparse(f, events=('end',)):
                if elem.tag.endswith('cpe-item'):
                    cpe_name = elem.get('name', '')
                    if cpe_name:
                        # parse CPE: cpe:/a:vendor:product:version
                        parts = cpe_name.split(':')
                        if len(parts) >= 4:
                            vendor = parts[2]
                            product = parts[3]
                            if product and vendor:
                                # Store multiple vendors for a product if they exist
                                if product not in CPE_MAPPING:
                                    CPE_MAPPING[product] = set()
                                CPE_MAPPING[product].add(vendor)
                    elem.clear()

        print(f"Loaded {len(CPE_MAPPING)} product entries from CPE dictionary", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to parse CPE dictionary: {e}", file=sys.stderr)

    return CPE_MAPPING

def lookup_vendor(pkgname, url=None, cpe_dict_path=None):
    if cpe_dict_path:
        load_cpe_dictionary(cpe_dict_path)

    # 1- try direct CPE dictionary lookup
    if CPE_MAPPING and pkgname in CPE_MAPPING:
        vendors = CPE_MAPPING[pkgname]
        return sorted(vendors)[0] if vendors else pkgname

    # 2- try common name variations in CPE dictionary
    if CPE_MAPPING:
        variations = [
            pkgname.replace('-', '_'),
            pkgname.replace('_', '-'),
            pkgname.replace('lib', ''),
            pkgname.replace('py-', ''),
            pkgname.replace('perl-', ''),
        ]

        for variant in variations:
            if variant in CPE_MAPPING:
                vendors = CPE_MAPPING[variant]
                return sorted(vendors)[0] if vendors else pkgname

    # 3- if no luck, fallback to package name
    return pkgname

def build_cpe_version(vendor, pkgname, pkgver):
    cpe_version = "cpe:2.3"
    vendor = vendor
    product_name = pkgname
    version = pkgver
    cpe = f"{cpe_version}:a:{vendor}:{product_name}:{version}:*:*:*:*:*:*:*"
    return cpe

def find_apkbuilds(root_dir):
    apkbuild_files = []
    for root, _, files in os.walk(root_dir):
        if 'APKBUILD' in files:
            apkbuild_files.append(os.path.join(root, 'APKBUILD'))
    return apkbuild_files

def find_cve_patch_files(directory):
    patches = []
    for filename in os.listdir(directory):
        filename = filename.lower()
        cve = CVE_PATTERN.search(filename)
        if cve:
            patches.append(cve.group(0).strip())
    return patches

def build_package_entry(apkbuild_path, tag, variables, pkgname=None, parent_pkgname=None):
    pkg = pkgname or variables['pkgname']
    vendor = variables.get('vendor', variables['pkgname'])

    entry = {
        'apkbuild_path': apkbuild_path,
        'alpine_tag': tag,
        'pkgname': pkg,
        'pkgver': variables['pkgver'],
        'pkgrel': variables['pkgrel'],
        '_myver': variables['_myver'],
        'pkgdesc': variables['pkgdesc'],
        'url': variables['url'],
        'license': variables['license'],
        'arch': variables['arch'],
        'alpine_ver': variables['alpine_ver'],
        'maintainer': variables['maintainer'],
        'secfixes': variables['secfixes'],
        'vendor': vendor,
        'cpe_alpine': build_cpe_version(pkg, pkg, variables['alpine_ver']),
        'cpe_vendor': build_cpe_version(vendor, pkg, variables['pkgver'])
    }

    if parent_pkgname:
        entry['parent_pkgname'] = parent_pkgname
    else:
        entry['subpackages'] = variables['subpackages']

    return entry

def extract_variables(apkbuild_path, cpe_dict_path=None):
    try:
        # extract the following variables from the APKBUILD
        variables = ['pkgname', 'pkgver', 'pkgrel', 'arch', 'subpackages',
                     '_myver', 'pkgdesc', 'url', 'license']
        sourced_vars = source_apkbuild(apkbuild_path, variables)

        # check for critical missing variables
        if not sourced_vars.get('pkgname') or not sourced_vars.get('pkgver') or not sourced_vars.get('pkgrel'):
            raise ValueError(f"Missing critical variables (pkgname, pkgver, or pkgrel) in {apkbuild_path}")

        sourced_vars['alpine_ver'] = sourced_vars['pkgver'] + "-r" + sourced_vars['pkgrel']
        if sourced_vars['subpackages']:
            sourced_vars['subpackages'] = [ sp.split(":")[0] for sp in sourced_vars['subpackages'].split() ]
        else:
            sourced_vars['subpackages'] = []

        # add maintainer and secfixes to the source_vars
        with open(apkbuild_path, 'r') as f:
            content = f.read()
            sourced_vars['maintainer'] = extract_maintainer(content)
            sourced_vars['secfixes'] = get_all_secfixes(content, find_cve_patch_files(os.path.dirname(apkbuild_path)))

        # lookup vendor using CPE dictionary and URL
        sourced_vars['vendor'] = lookup_vendor(
            sourced_vars['pkgname'],
            sourced_vars.get('url'),
            cpe_dict_path
        )

        return sourced_vars
    except Exception as e:
        print(f"Error extracting variables from {apkbuild_path}: {e}", file=sys.stderr)
        raise

def main(tag, input_dir, output_path, cpe_dict_path=None):
    try:
        root_dir = os.path.abspath(input_dir)
        if not os.path.exists(root_dir):
            print(f"Error: Input directory does not exist: {root_dir}", file=sys.stderr)
            sys.exit(1)

        # load CPE dictionary once at startup
        if cpe_dict_path:
            load_cpe_dictionary(cpe_dict_path)

        print(f"Searching for APKBUILD files in: {root_dir}")
        apkbuild_files = find_apkbuilds(root_dir)
        if not apkbuild_files:
            print("Error: No APKBUILD files found.", file=sys.stderr)
            sys.exit(1)

        results = []
        failed_count = 0
        for apkbuild in apkbuild_files:
            try:
                variables = extract_variables(apkbuild, cpe_dict_path)
                relative_path = os.path.relpath(apkbuild, root_dir)

                # add the main package
                results.append(build_package_entry(relative_path, tag, variables))

                # add subpackages
                for subpackage in variables['subpackages']:
                    results.append(build_package_entry(
                        relative_path,
                        tag,
                        variables,
                        pkgname=subpackage,
                        parent_pkgname=variables['pkgname']
                    ))
            except Exception as e:
                failed_count += 1
                print(f"Error processing {apkbuild}: {e}", file=sys.stderr)
                # continue processing other files but track failures

        if not results:
            print("Error: No packages were successfully processed.", file=sys.stderr)
            sys.exit(1)

        # dump results to JSON file
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, 'w') as json_file:
            json.dump(results, json_file, indent=4)

        print(f"Results saved to {output_path}")
        print(f"Successfully processed {len(apkbuild_files) - failed_count}/{len(apkbuild_files)} APKBUILD files")

        if failed_count > 0:
            print(f"Warning: {failed_count} files failed to process", file=sys.stderr)
            sys.exit(2)  # exit with code 2 to indicate partial success

    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python get_package_info.py <tag> <input_dir> <output_file> [cpe_dict_path]", file=sys.stderr)
        sys.exit(1)

    cpe_dict = sys.argv[4] if len(sys.argv) > 4 else None
    try:
        main(sys.argv[1], sys.argv[2], sys.argv[3], cpe_dict)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)