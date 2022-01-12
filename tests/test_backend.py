# SPDX-License-Identifier: LGPL-2.1+

import os
import unittest

from mkosi.backend import PackageType, Distribution, set_umask

class BackendTests(unittest.TestCase):
    def test_distribution(self):
        self.assertEqual(Distribution.fedora.package_type, PackageType.rpm)
        self.assertIs(Distribution.fedora, Distribution.fedora)
        self.assertIsNot(Distribution.fedora,  Distribution.debian)
        self.assertEqual(str(Distribution.photon), "photon")


    def test_set_umask(self):
        with set_umask(0o767):
            tmp1 = os.umask(0o777)
            with set_umask(0o757):
                tmp2 = os.umask(0o727)
            tmp3 = os.umask(0o727)

        self.assertEqual(tmp1, 0o767)
        self.assertEqual(tmp2, 0o757)
        self.assertEqual(tmp3, 0o777)
