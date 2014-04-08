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
import sys, os, shutil
import unittest
import tempfile
import ConfigParser
import optparse
from tempfile import tempdir
DYNAMIC_SERVICES_SECTION = 5;
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../files/scripts/public'))
from volatile_dir_control import ConfigModify, DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION

PRIV_CONF_NAME = 'ls-private.conf'
PUB_CONF_NAME = 'ls-public.conf'

def get_file_content(path):
    with open(path) as f:
        return f.read()

class TestVolatileDirControl(unittest.TestCase):

    def setUp(self):
        self.conf_dir_name = tempfile.mkdtemp(dir='/tmp/')

    def tearDown(self):
        shutil.rmtree(self.conf_dir_name)

    def _test_const_conf(self, conf_file_name):
        self.readonly_conf_parser = ConfigParser.SafeConfigParser()
        self.readonly_conf_parser.read(os.path.join(options.readonly_config_dir, conf_file_name))
        self.assert_(self.readonly_conf_parser.has_section(DYNAMIC_SERVICES_SECTION))
        self.assert_(self.readonly_conf_parser.has_option(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION))

    def test_const_conf(self):
        self._test_const_conf(PRIV_CONF_NAME)
        self._test_const_conf(PUB_CONF_NAME)

    def _test_add(self, conf_name):
        self._test_const_conf(conf_name)

        conf_parser = ConfigParser.SafeConfigParser()
        conf_parser.read(os.path.join(self.conf_dir_name, conf_name))

        if conf_parser.has_section(DYNAMIC_SERVICES_SECTION) and conf_parser.has_option(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION) :
            was = conf_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION)
        else:
            was = self.readonly_conf_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION)

        ConfigModify(conf_name, options.readonly_config_dir, self.conf_dir_name).add(self.conf_dir_name)
        conf_parser.read(os.path.join(self.conf_dir_name, conf_name))
        self.assert_(conf_parser.has_section(DYNAMIC_SERVICES_SECTION))
        self.assert_(conf_parser.has_option(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION))

        become = conf_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION)
        self.assertEqual(was + ';' + self.conf_dir_name,
                         become,
                         "wrong value in new file: " + become)

    def test_add_private(self):
        self._test_add(PRIV_CONF_NAME)

    def test_add_public(self):
        self._test_add(PUB_CONF_NAME)

    def _test_remove(self, conf_name):
        self._test_add(conf_name)
        ConfigModify(conf_name, options.readonly_config_dir, self.conf_dir_name).remove(self.conf_dir_name)

        conf_parser = ConfigParser.SafeConfigParser()
        conf_parser.read(os.path.join(self.conf_dir_name, conf_name))
        self.assert_(conf_parser.has_section(DYNAMIC_SERVICES_SECTION))
        self.assert_(conf_parser.has_option(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION))

        was = self.readonly_conf_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION)
        become = conf_parser.get(DYNAMIC_SERVICES_SECTION, VOLATILE_DIRS_OPTION)
        self.assertEqual(was,
                         become.replace(';'+self.conf_dir_name, ''),
                         "wrong value in new file: " + become)

    def test_remove_private(self):
        self._test_remove(PRIV_CONF_NAME)

    def test_remove_public(self):
        self._test_remove(PUB_CONF_NAME)

    def _test_consistency(self, conf_name):
        const_conf_was = get_file_content(os.path.join(options.readonly_config_dir, conf_name))
        self._test_const_conf(conf_name)
        self._test_add(conf_name)

        const_conf_become = get_file_content(os.path.join(options.readonly_config_dir, conf_name))
        self.assertEqual(const_conf_was, const_conf_become, 'Readonly conf changed')

        self._test_remove(conf_name)

    def test_consistency_pub(self):
        self._test_consistency(PUB_CONF_NAME)

    def test_consistency_priv(self):
        self._test_consistency(PRIV_CONF_NAME)


USAGE = '''%s [OPTIONS]
  -c, --config-dir   # sets readonly config path (no changes)
''' % sys.argv[0]

if __name__ == '__main__':
    parser = optparse.OptionParser(usage=USAGE)
    parser.add_option("-c", "--config-dir",
                      action="store", type="string", dest="readonly_config_dir")

    global options
    options, args = parser.parse_args()
    if not options.readonly_config_dir:
        parser.error('FAILED wrong arguments %s' % ' '.join(args))
        sys.exit(-1)

    unittest.TestProgram('__main__', None, [sys.argv[0], '-v'])
