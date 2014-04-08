#! /usr/bin/python2
# @@@LICENSE
#
#      Copyright (c) 2014 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@
import os, sys
import ConfigParser
import optparse
import fcntl

USAGE = '''%s [OPTIONS]
  -a, --add      # adds directory to read permissions from
  -r, --remove   # removes directory to read permissions from
  -b, --bus-type # public or private (mandatory option)
''' % sys.argv[0]

GENERAL_SECTION = 'General'
DYNAMIC_SERVICES_SECTION = 'Dynamic Services'
OVERLAY_DIR_OPTION = 'Overlay'
VOLATILE_DIRS_OPTION = 'VolatileDirectories'

class ConfigModify :

    def __init__(self, config_file_name,
                 readonly_conf_dir, # '/etc/luna-service2'
                 dynamic_conf_dir): # '/var/run/ls2'
        self.dynamic_conf_path = os.path.join(dynamic_conf_dir, config_file_name)
        self.parser = ConfigParser.SafeConfigParser()
        self.parser.read(self.dynamic_conf_path)

        if not self.parser.has_section(DYNAMIC_SERVICES_SECTION) :
            self.parser.add_section(DYNAMIC_SERVICES_SECTION)

        if self.parser.has_option(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION) :
            effective_parser = self.parser
        else:
            effective_parser = ConfigParser.SafeConfigParser()
            effective_parser.read(os.path.join(readonly_conf_dir, config_file_name))

        self.volatile = effective_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION).split(';')

    def add(self, path):
        self.volatile.append(path)
        self.set_volatile_dirs()

    def set_volatile_dirs(self):
        self.parser.set(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION, ';'.join(self.volatile))

    def remove(self, path):
        self.volatile.remove(path)
        self.set_volatile_dirs()

    def __del__(self) :
        tmp_write_path = self.dynamic_conf_path + '~'
        with os.fdopen(os.open(tmp_write_path,
                               os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                               0600),
                       'w') as dynamic_conf_file :
            self.parser.write(dynamic_conf_file)
        os.rename(tmp_write_path, self.dynamic_conf_path)

def main():
    parser = optparse.OptionParser(usage=USAGE)
    parser.add_option("-a", "--add",
                      action="store", type="string", dest="add")
    parser.add_option("-r", "--remove",
                      action="store", type="string", dest="remove")
    parser.add_option("-b", "--bus-type",
                      action="store", type="string", dest="bus")

    options, args = parser.parse_args()
    if not options.bus or not (options.add or options.remove) :
        parser.error('FAILED wrong arguments %s' % ' '.join(args))
        sys.exit(-1)

    CONFIG_FILE_NAME = 'ls-' + options.bus + '.conf'

    import volatile_dir_control_settings
    readonly_conf_dir = volatile_dir_control_settings.CONST_CONF_DIR
    readonly_conf_parser = ConfigParser.SafeConfigParser()
    readonly_conf_parser.read(os.path.join(readonly_conf_dir, CONFIG_FILE_NAME))
    dynamic_conf_dir = readonly_conf_parser.get(GENERAL_SECTION, OVERLAY_DIR_OPTION)

    fp = open(os.path.join(dynamic_conf_dir, '.volatile-dir-control.lock'), 'w')
    fcntl.flock(fp, fcntl.LOCK_EX)

    if options.add:
        ConfigModify(CONFIG_FILE_NAME, readonly_conf_dir, dynamic_conf_dir).add(options.add)
    elif options.remove:
        ConfigModify(CONFIG_FILE_NAME, readonly_conf_dir, dynamic_conf_dir).remove(options.remove)
    else:
        print USAGE;
        sys.exit(-1)

    sys.exit(0)

if __name__ == '__main__':
    main()
