"""
This script automatically increments the IPv8 setup.py version and creates a changelog message for it on GitHub.
You are tasked with opening a PR from your fork.

IMPORTANT: THIS SCRIPT ASSUMES THAT YOUR LOCAL WORKSPACE IS CLEAN. DO NOT RUN THIS SCRIPT WITH UNCOMMITTED CHANGES!

Other caveats:
 - Claims the local branchname ``__automated_version_update``, which may not be cleaned on error.
 - Claims the remote branchname ``automated_version_update`` on your GitHub fork.
 - Adds the local remote ``__Tribler``, which may not be cleaned on error!
 - Adds the local remote ``__<username>``, which may not be cleaned on error!

The local branch and local remotes should not exist before running this script.
"""
from __future__ import annotations

import ast
import datetime
import subprocess
import sys
from typing import cast

from packaging.version import Version

# ruff: noqa: S602, S607, T201


def parse_setup() -> tuple[str, ast.Expr]:
    """
    Search for the ``setup(...)`` expression in ``setup.py`` and return its AST node.

    We later update the ``version=...`` parameter.
    """
    print("[1/8] | Parsing setup.py file.")

    with open("setup.py") as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, "setup.py")

    setup_expression = None
    for element in treeobj.body:
        if isinstance(element, ast.Expr) and cast("ast.Name", cast("ast.Call", element.value).func).id == "setup":
            setup_expression = element

    if not setup_expression:
        print("No setup() found in setup.py!")
        sys.exit(1)

    return file_contents, setup_expression


def parse_doc_conf() -> tuple[str, tuple[ast.Constant, ast.Constant, ast.Constant]]:
    """
    Search for ``copyright = ...``, ``version = ...``, and ``release = ...`` in ``doc/conf.py``
    and return their AST nodes.
    """
    print("[1/8] | Parsing doc/conf.py file.")

    with open("doc/conf.py") as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, "doc/conf.py")

    copyright_element = None
    version_element = None
    release_element = None
    for element in treeobj.body:
        if isinstance(element, ast.Assign) and isinstance(element.value, ast.Constant):
            if cast("ast.Name", element.targets[0]).id == "copyright":
                copyright_element = element.value
            elif cast("ast.Name", element.targets[0]).id == "version":
                version_element = element.value
            elif cast("ast.Name", element.targets[0]).id == "release":
                release_element = element.value

    if not copyright_element:
        print("No 'copyright' assignment found in doc/conf.py!")
        sys.exit(1)
    if not version_element:
        print("No 'version' assignment found in doc/conf.py!")
        sys.exit(1)
    if not release_element:
        print("No 'release' assignment found in doc/conf.py!")
        sys.exit(1)

    return file_contents, (copyright_element, version_element, release_element)


def parse_rest_manager() -> tuple[str, ast.Constant]:
    """
    Search for ``aiohttp_apispec = AiohttpApiSpec(...)`` in ``ipv8/REST/rest_manager.py``
    and return the ``version=...`` parameter AST node.
    """
    print("[1/8] | Parsing ipv8/REST/rest_manager.py file.")

    with open("ipv8/REST/rest_manager.py") as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, "ipv8/REST/rest_manager.py")

    version_element = None
    for element in treeobj.body:
        if isinstance(element, ast.ClassDef) and element.name == "RESTManager":
            for inner_definition in element.body:
                if isinstance(inner_definition, ast.AsyncFunctionDef) and inner_definition.name == "start":
                    for f_statement in inner_definition.body:
                        if (isinstance(f_statement, ast.Assign)
                                and f_statement.targets
                                and isinstance(f_statement.targets[0], ast.Name)
                                and cast("ast.Name", f_statement.targets[0]).id == "aiohttp_apispec"
                                and isinstance(f_statement.value, ast.Call)
                                and isinstance(f_statement.value.func, ast.Name)
                                and f_statement.value.func.id == "AiohttpApiSpec"):
                            for setup_arg in f_statement.value.keywords:
                                if setup_arg.arg == "version":
                                    version_element = setup_arg.value

    if not version_element:
        print("No 'version' assignment found in ipv8/REST/rest_manager.py!")
        sys.exit(1)

    return file_contents, cast("ast.Constant", version_element)


def modify_setup(file_contents: str, setup_expression: ast.Expr) -> tuple[str, str, str, str, str]:
    """
    Rewrite the ``setup.py`` contents by modifying the ``setup(...)`` AST node.
    """
    print("[2/8] | Modifying setup.py file.")
    new_filecontents = ""
    old_version = ""
    old_version_tag = ""
    new_version = ""
    new_version_tag = ""
    for keyword in cast("ast.Call", setup_expression.value).keywords:
        if keyword.arg == "version":
            lineno = keyword.value.lineno
            coloffset = keyword.value.col_offset
            old_version = cast("ast.Name", keyword.value).s
            version = Version(old_version)

            new_vstring = [version.major, version.minor, version.micro]
            old_version_tag = ".".join(str(s) for s in new_vstring[:2])
            new_vstring[1] += 1
            new_version = ".".join(str(s) for s in new_vstring)
            new_version_tag = ".".join(str(s) for s in new_vstring[:2])

            new_split_filecontents = file_contents.splitlines(True)
            source_line = new_split_filecontents[lineno - 1]
            new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                                  + new_version
                                                  + source_line[len(old_version) + coloffset + 1:])
            new_filecontents = "".join(new_split_filecontents)
            break
    return old_version, old_version_tag, new_version, new_version_tag, new_filecontents


def modify_docs(file_contents: str, ast_elements: tuple[ast.Constant, ast.Constant, ast.Constant],
                new_version: str, new_version_tag: str) -> str:
    """
    Rewrite the ``conf.py`` contents by modifying the ``copyright``, ``version``, and ``release`` values.
    """
    print("[2/8] | Modifying doc/conf.py file.")

    to_insert = [f"2017-{datetime.datetime.now().year}, Tribler",  # noqa: DTZ005
                 new_version_tag,
                 new_version]

    new_split_filecontents = file_contents.splitlines(True)
    for i, element in enumerate(ast_elements):
        lineno = element.lineno
        coloffset = element.col_offset
        old_version = element.s

        source_line = new_split_filecontents[lineno - 1]
        new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                              + to_insert[i]
                                              + source_line[len(old_version) + coloffset + 1:])

    return "".join(new_split_filecontents)


def modify_rest_manager(file_contents: str, element: ast.Constant, new_version_tag: str) -> str:
    """
    Rewrite the ``rest_manager.py`` contents by modifying the ``version=`` constructor parameter.
    """
    print("[2/8] | Modifying ipv8/REST/rest_manager.py file.")

    new_split_filecontents = file_contents.splitlines(True)

    lineno = element.lineno
    coloffset = element.col_offset
    old_version = element.s

    source_line = new_split_filecontents[lineno - 1]
    new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                          + f"v{new_version_tag}"
                                          + source_line[len(old_version) + coloffset + 1:])

    return "".join(new_split_filecontents)


print("[1/8] Parsing source files.")
old_setup_file, setup_ast = parse_setup()
old_docs_file, docs_ast_elements = parse_doc_conf()
old_rest_manager_file, rest_manager_ast = parse_rest_manager()

print("[2/8] Modifying source files.")
old_version, old_version_tag, new_version, new_version_tag, new_setup_file = modify_setup(old_setup_file, setup_ast)
new_docs_file = modify_docs(old_docs_file, docs_ast_elements, new_version, new_version_tag)
new_rest_manager_file = modify_rest_manager(old_rest_manager_file, rest_manager_ast, new_version_tag)

# LOGIN
print("[3/8] Requesting GitHub username.")

username = input("Username: ")

# GET REPOSITORY REFERENCES
print(f"[4/8] Retrieving Tribler:py-ipv8 and {username}:py-ipv8.")

# branchname or "HEAD"
original_branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", encoding="utf-8", shell=True).strip()
if original_branch == "HEAD":
    # HEAD, origin/main, origin/HEAD
    detached_details = subprocess.check_output("git show -s --pretty=%D HEAD", encoding="utf-8", shell=True)
    original_branch = detached_details.split(", ")[1].strip()

print(subprocess.check_output(f"git remote add __{username} git@github.com:{username}/py-ipv8.git", encoding="utf-8", shell=True))
print(subprocess.check_output("git remote add __Tribler git@github.com:Tribler/py-ipv8.git", encoding="utf-8", shell=True))

print(subprocess.check_output("git fetch __Tribler master", encoding="utf-8", shell=True))
print(subprocess.check_output("git checkout -b __automated_version_update __Tribler/master", encoding="utf-8", shell=True))

# GET CHANGES
print("[5/8] Calculating changes since last release.")

known_tags = sorted(Version(t) for t in subprocess.check_output("git tag -l", encoding="utf-8", shell=True).split())
last_release_commit, = subprocess.check_output(f"git rev-list -n 1 {known_tags[-1]}", encoding="utf-8", shell=True).split()

git_log = subprocess.check_output(f'git log {last_release_commit}..HEAD --pretty=format:"%H"',
                                  encoding="utf-8", shell=True).split("\n")
git_log = [
    (
        subprocess.check_output(f"git log --format=%B -n 1  {sha_entry}", encoding="utf-8", shell=True).split("\n")[0],
        subprocess.check_output(f"git log --format=%b -n 1  {sha_entry}", encoding="utf-8", shell=True).split("\n")[0]
    )
    for sha_entry in git_log
]
commits_since_last = len(git_log) + 2

total_commits_str = subprocess.check_output("git rev-list --count HEAD", encoding="utf-8", shell=True)
total_commits = int(total_commits_str) + 2

# PERFORM FILE REWRITES
print("[6/8] Rewriting source files.")

with open("setup.py", "w") as f:
    f.write(new_setup_file)
with open("doc/conf.py", "w") as f:
    f.write(new_docs_file)
with open("ipv8/REST/rest_manager.py", "w") as f:
    f.write(new_rest_manager_file)

# CREATE FEATURE BRANCH
print("[7/8] Pushing changes to branch on fork.")

print(subprocess.check_output("git add setup.py", encoding="utf-8", shell=True))
print(subprocess.check_output("git add doc/conf.py", encoding="utf-8", shell=True))
print(subprocess.check_output("git add ipv8/REST/rest_manager.py", encoding="utf-8", shell=True))
print(subprocess.check_output('git commit -m "Automated version increment"', encoding="utf-8", shell=True))
print(subprocess.check_output(f"git push -f -u __{username} __automated_version_update:automated_version_update",
                              encoding="utf-8", shell=True))

# > Cleanup
print(subprocess.check_output(f"git checkout {original_branch}", encoding="utf-8", shell=True))
print(subprocess.check_output("git branch -D __automated_version_update", encoding="utf-8", shell=True))
print(subprocess.check_output("git remote remove __Tribler", encoding="utf-8", shell=True))
print(subprocess.check_output(f"git remote remove __{username}", encoding="utf-8", shell=True))

# CREATE PULL REQUEST
print("[8/8] Formatting Pull Request message")
print("vv OUTPUT vv")


def commit_messages_to_names(commit_msg_list: list[str]) -> list[str]:
    """
    Humans are not computers. Correct some common mistakes.
    """
    out = []
    misspellings = {
        "add ": "Added ",
        "Add ": "Added ",
        "ADD ": "Added ",
        "added ": "Added ",
        "ADDED ": "Added ",
        "fix ": "Fixed ",
        "Fix ": "Fixed ",
        "FIX ": "Fixed ",
        "fixed ": "Fixed ",
        "FIXED ": "Fixed ",
        "update ": "Updated ",
        "Update ": "Updated ",
        "UPDATE ": "Updated ",
        "updated ": "Updated ",
        "UPDATED ": "Updated ",
        "remove ": "Removed ",
        "Remove ": "Removed ",
        "REMOVE ": "Removed ",
        "removed ": "Removed ",
        "REMOVED ": "Removed "
    }
    residual_prefixes = {
        "READY: ": "",
        "ready: ": "",
        "Ready: ": "",
        "READY ": "",
        "ready ": "",
        "Ready ": "",
        "WIP: ": "",
        "wip: ": "",
        "Wip: ": "",
        "WIP ": "",
        "wip ": "",
        "Wip ": "",
        "[READY] ": "",
        "[WIP] ": ""
    }
    for commit_msg in commit_msg_list:
        corrected = commit_msg
        # First, strip residual prefixes, e.g. "READY: Add some feature" -> "Add some feature".
        for mistake, correction in residual_prefixes.items():
            if commit_msg.startswith(mistake):
                corrected = correction + commit_msg[len(mistake):]
        # Second, modify misspellings, e.g. "Add some feature" -> "Added some feature".
        # We do this after the first step to correct compound errors (both leaving the prefix AND not adhering to
        # the naming standard).
        for mistake, correction in misspellings.items():
            if corrected.startswith(mistake):
                corrected = correction + corrected[len(mistake):]
        out.append(corrected)
    return sorted(out)


print("Title: Automated Version Update")
print(f"Tag version: {new_version_tag}")
print(f"Release title: IPv8 v{new_version_tag}.{total_commits} release")
print(f"Body:\n"
      f"Includes the first {total_commits} commits (+{commits_since_last} since v{old_version_tag}) "
      "for IPv8, containing:\n\n - "
      + ("\n - ".join(commit_messages_to_names([c[1] for c in git_log if c[0].startswith("Merge")]))))
