# -*- coding: utf-8 -*-
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, 'libs'))

from utm_stack import ConfigMan

if __name__ == '__main__':
    ConfigMan().delete_data()
