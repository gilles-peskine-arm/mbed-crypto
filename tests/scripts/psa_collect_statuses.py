#!/usr/bin/env python3
"""Measure the test coverage of PSA functions in terms of return statuses.

1. Build with -DRECORD_PSA_STATUS_COVERAGE_LOG
2. Run psa_collect_statuses.py
"""

import argparse
import os
import subprocess
import sys

_default_status_log_file = 'tests/statuses.log'
_default_psa_constant_names = 'programs/psa/psa_constant_names'

class Statuses:
    def __init__(self):
        self.functions = {}
        self.codes = set()
        self.status_names = {}

    def collect_log(self, log_file_name):
        with open(log_file_name) as log:
            for line in log:
                value, function, tail = line.split(':', 2)
                if function not in self.functions:
                    self.functions[function] = {}
                fdata = self.functions[function]
                if value not in self.functions[function]:
                    fdata[value] = []
                fdata[value].append(tail)
                self.codes.add(int(value))

    def get_constant_names(self, psa_constant_names):
        values = [str(value) for value in self.codes]
        cmd = [psa_constant_names, 'status'] + values
        output = subprocess.check_output(cmd).decode('ascii')
        for value, name in zip(values, output.rstrip().split('\n')):
            self.status_names[value] = name

    def report(self):
        for function in sorted(self.functions.keys()):
            fdata = self.functions[function]
            names = [self.status_names[value] for value in fdata.keys()]
            for name in sorted(names):
                sys.stdout.write('{} {}\n'.format(function, name))

def collect_status_logs(options):
    rebuilt = False
    if not options.use_existing_log and os.path.exists(options.log_file):
            os.remove(options.log_file)
    if not os.path.exists(options.log_file):
        if options.clean_before:
            subprocess.check_call(['make', 'clean'],
                                  cwd='tests',
                                  stdout = sys.stderr)
        with open(os.devnull, 'w') as devnull:
            make_q_ret = subprocess.call(['make', '-q'],
                                         stdout=devnull, stderr=devnull)
        if make_q_ret != 0:
            subprocess.check_call(['make', 'RECORD_PSA_STATUS_COVERAGE_LOG=1'],
                                  stdout = sys.stderr)
            rebuilt = True
        subprocess.check_call(['make', 'test'],
                              stdout = sys.stderr)
    data = Statuses()
    data.collect_log(options.log_file)
    data.get_constant_names(options.psa_constant_names)
    if rebuilt and options.clean_after:
        subprocess.check_call(['make', 'clean'],
                              cwd='tests',
                              stdout = sys.stderr)
    return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--clean-after',
                        action='store_true',
                        help='Run "make clean" after rebuilding')
    parser.add_argument('--clean-before',
                        action='store_true',
                        help='Run "make clean" before regenerating the log file)')
    parser.add_argument('--log-file', metavar='FILE',
                        default=_default_status_log_file,
                        help='Log file location (default: {})'.format(_default_status_log_file))
    parser.add_argument('--psa-constant-names', metavar='PROGRAM',
                        default=_default_psa_constant_names,
                        help='Path to psa_constant_names (default: {})'.format(_default_psa_constant_names))
    parser.add_argument('--use-existing-log', '-e',
                        action='store_true',
                        help='Don\'t regenerate the log file if it exists')
    options = parser.parse_args()
    data = collect_status_logs(options)
    data.report()
