# -*- coding: utf-8 -*-
import unittest
from py_inspector import verificadores


class ValidandoPython(unittest.TestCase, verificadores.TestValidacaoPython):
    def __init__(self, *args, **kwargs):
        unittest.TestCase.__init__(self, *args, **kwargs)
        verificadores.TestValidacaoPython.__init__(self)
        self.pylint_args.extend([
            '--class-attribute-rgx=([A-Za-z_][A-Za-z0-9_]{2,60}|(__.*__))$',
            '--max-locals=20',
            '--max-args=20',
            '--max-attributes=20',
            '--min-public-methods=0'
        ])
