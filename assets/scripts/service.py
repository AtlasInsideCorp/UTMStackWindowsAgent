import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), 'libs'))
from utm_agent.service import main

main()
