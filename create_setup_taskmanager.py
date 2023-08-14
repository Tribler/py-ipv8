"""
Extract and rewrite ``ipv8.taskmanager`` to be a standalone package (``ipv8_taskmanager``).

Install your newly created package using `cd ipv8_taskmanager && pip install .`
"""
from __future__ import annotations

import ast
import importlib
import logging
import os
import typing

import ipv8.taskmanager

MissingImport = typing.NamedTuple("MissingImport", ["node", "stmt", "alias"])
TASKMNGR_FILE = ipv8.taskmanager.__file__
TASKMNGR_FOLDER = os.path.dirname(TASKMNGR_FILE)
TARGET_TMP_DIR = "ipv8_taskmanager"
TARGET_FOLDER = os.path.join(TARGET_TMP_DIR, "ipv8_taskmanager")
TARGET_FILE = os.path.join(TARGET_FOLDER, "__init__.py")
LINESEP = "\n"


def prepare_folder() -> None:
    """
    Make sure the target folder does not exist.
    We don't want a user to accidentally overwrite his files.

    :returns: None
    """
    try:
        os.makedirs(TARGET_FOLDER, mode=0o777, exist_ok=False)
    except FileExistsError as e:
        logging.exception("The ipv8_taskmanager folder already exists. "
                      "Please check that you are not overwriting something important and "
                      "delete the folder manually.")
        raise e  # noqa: TRY201


def find_missing_imports(tree: ast.AST) -> list[MissingImport]:
    """
    Try to find any imports that the tree requires.

    We can inject ``from x import y`` imports straight into the source file.
    We error out on ``import x`` imports.
    "injectable-but-missing" imports are returned as ``MissingImport`` tuples.

    :return: the list of missing imports
    """
    missing = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                stmt = f"import {alias.name}"
                try:
                    exec(stmt, {}, {})  # noqa: S102
                except ModuleNotFoundError as e:
                    logging.exception("Unimportable modules are not allowed!")
                    raise e  # noqa: TRY201
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                stmt = f"from {node.module} import {alias.name}"
                try:
                    exec(stmt, {}, {})  # noqa: S102
                except ModuleNotFoundError:
                    missing.append(MissingImport(node=node, stmt=stmt, alias=alias.name))
    return missing


def copy_node_as_src(node: ast.AST, lines: dict[int, str]) -> str:
    """
    Get the source code an AST node is defined on.

    :return: the source code of the given node
    """
    output = ""
    for l in range(node.lineno, node.end_lineno + 1):
        output += lines[l] + LINESEP
    return output


def fetch(missing: MissingImport) -> tuple[str, typing.Set[str], typing.Set[str]]:
    """
    Get the code required to satisfy a missing import.

    For example, if you ``from a import b``. This will return all imports, module level definitions and the
    function ``b``. Suppose you have the following ``a.py``, you would get the lines marked with ``YES``:

     .. code-block :: Python

        import math  # YES
        SOME_GLOBAL = 1  # YES
        def b():  # YES
            return 1  # YES
        def c():  # NO
            return 2  # NO

    :param missing: the import to fetch the required code for
    :return: the code required for the missing import
    """
    missing_module = importlib.import_module("." * missing.node.level + missing.node.module, "ipv8")

    with open(missing_module.__file__) as source_file:
        source = source_file.read()
    tree = ast.parse(source, filename=missing_module.__file__)
    lines = {i + 1: line for i, line in enumerate(source.split(LINESEP))}

    output = ""
    imports = set()
    toplevel_vars = set()

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            imports.add(copy_node_as_src(node, lines))
        elif isinstance(node, ast.Assign):
            toplevel_vars.add(copy_node_as_src(node, lines))
        elif isinstance(node, ast.FunctionDef) and node.name == missing.alias:
            output += LINESEP + LINESEP + copy_node_as_src(node, lines)

    return output, imports, toplevel_vars


def read_tskmngr_source() -> tuple[ast.AST, str, dict[int, str]]:
    """
    Parse the ``ipv8.taskmanager`` code and return an AST node and the source code as both str and list-of-lines form.

    :return: the ast node, the full source code, the source code as a list of lines
    """
    with open(TASKMNGR_FILE) as source_file:
        source = source_file.read()
    tree = ast.parse(source, filename=TASKMNGR_FILE)

    lines = {i + 1: line for i, line in enumerate(source.split(LINESEP))}

    return tree, source, lines


def extract_taskmanager() -> None:
    """
    Rewrite the ``ipv8.taskmanager`` to be standalone.
    Put the result in ``ipv8_taskmanager/ipv8_taskmanager``.

    :returns: None
    """
    prepare_folder()

    tree, source, lines = read_tskmngr_source()
    missing_imports = find_missing_imports(tree)

    for replaced in {missing.node.lineno for missing in missing_imports}:
        lines.pop(replaced)

    new_toplevel_imports = set()
    new_toplevel_vars = set()
    for missing in missing_imports:
        line_num = missing.node.lineno
        source = lines.get(line_num, "")
        missing_output, nimports, ntoplevel_vars = fetch(missing)
        new_toplevel_imports |= nimports
        new_toplevel_vars |= ntoplevel_vars
        source += missing_output
        lines[line_num] = source

    # Add imports
    lines[0] = "".join(new_toplevel_imports) + LINESEP + "".join(new_toplevel_vars)

    # Turn into source code
    raw_source = "".join(lines[l] + LINESEP for l in sorted(lines))

    # Write to file
    with open(TARGET_FILE, "w") as f:
        f.write(raw_source)


def make_setup() -> None:
    """
    Create ``ipv8_taskmanager/setup.py``.

    :returns: None
    """
    with open(os.path.join(TARGET_TMP_DIR, "setup.py"), "w") as f:
        f.write("""from setuptools import find_packages, setup
setup(
    name='ipv8_taskmanager',
    author='Tribler',
    description='The IPv8 TaskManager',
    long_description=('This module provides a set of tools to maintain a list of asyncio Tasks that are to be '
                      'executed during the lifetime of an arbitrary object, usually getting killed with it. This '
                      'module is extracted from the IPv8 main project.'),
    long_description_content_type='text/markdown',
    version='1.0.0',
    url='https://github.com/Tribler/py-ipv8',
    package_data={'': ['*.*']},
    packages=find_packages(),
    py_modules=[],
    install_requires=[],
    extras_require={},
    tests_require=[],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
""")


if __name__ == "__main__":
    extract_taskmanager()
    make_setup()
