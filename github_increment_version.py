from __future__ import absolute_import, print_function

import ast
import sys
from distutils.version import LooseVersion

with open('setup.py', 'r') as f:
    filecontents = f.read()

treeobj = ast.parse(filecontents, 'setup.py')

setup_expression = None
for element in treeobj.body:
    if isinstance(element, ast.Expr) and element.value.func.id == "setup":
        setup_expression = element

if not setup_expression:
    print("No setup() found in setup.py")
    sys.exit(1)

for keyword in setup_expression.value.keywords:
    if keyword.arg == "version":
        lineno = keyword.value.lineno
        coloffset = keyword.value.col_offset
        raw_version = keyword.value.s
        version = LooseVersion(raw_version)

        new_vstring = version.version
        new_vstring[1] += 1
        new_version = '.'.join(str(s) for s in new_vstring)

        new_split_filecontents = filecontents.splitlines(True)
        source_line = new_split_filecontents[lineno - 1]
        new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                              + new_version
                                              + source_line[len(raw_version) + coloffset + 1:])
        new_filecontents = "".join(new_split_filecontents)

        with open('setup.py', 'w') as f:
            f.write(new_filecontents)
