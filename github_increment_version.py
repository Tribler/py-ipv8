"""
This script automatically increments the IPv8 setup.py version and creates a PR for it on GitHub.
The suggested release message is used as the PR body.

This script requires the additional dependency PyGithub.
"""
from __future__ import annotations

import ast
import datetime
import getpass
import sys
from typing import cast

from github import Github, InputGitTreeElement
from packaging.version import Version


def parse_setup() -> tuple[str, ast.Expr]:
    """
    Search for the ``setup(...)`` expression in ``setup.py`` and return its AST node.

    We later update the ``version=...`` parameter.
    """
    print("[1/8] | Parsing setup.py file")  # noqa: T201

    with open('setup.py') as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, 'setup.py')

    setup_expression = None
    for element in treeobj.body:
        if isinstance(element, ast.Expr) and cast(ast.Name, cast(ast.Call, element.value).func).id == "setup":
            setup_expression = element

    if not setup_expression:
        print("No setup() found in setup.py")  # noqa: T201
        sys.exit(1)

    return file_contents, setup_expression


def parse_doc_conf() -> tuple[str, tuple[ast.Constant, ast.Constant, ast.Constant]]:
    """
    Search for ``copyright = ...``, ``version = ...``, and ``release = ...`` in ``doc/conf.py``
    and return their AST nodes.
    """
    print("[1/8] | Parsing doc/conf.py file")  # noqa: T201

    with open('doc/conf.py') as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, 'doc/conf.py')

    copyright_element = None
    version_element = None
    release_element = None
    for element in treeobj.body:
        if isinstance(element, ast.Assign) and isinstance(element.value, ast.Constant):
            if cast(ast.Name, element.targets[0]).id == "copyright":
                copyright_element = element.value
            elif cast(ast.Name, element.targets[0]).id == "version":
                version_element = element.value
            elif cast(ast.Name, element.targets[0]).id == "release":
                release_element = element.value

    if not copyright_element:
        print("No 'copyright' assignment found in doc/conf.py")  # noqa: T201
        sys.exit(1)
    if not version_element:
        print("No 'version' assignment found in doc/conf.py")  # noqa: T201
        sys.exit(1)
    if not release_element:
        print("No 'release' assignment found in doc/conf.py")  # noqa: T201
        sys.exit(1)

    return file_contents, (copyright_element, version_element, release_element)


def parse_rest_manager() -> tuple[str, ast.Constant]:
    """
    Search for ``aiohttp_apispec = AiohttpApiSpec(...)`` in ``ipv8/REST/rest_manager.py``
    and return the ``version=...`` parameter AST node.
    """
    print("[1/8] | Parsing ipv8/REST/rest_manager.py file")  # noqa: T201

    with open('ipv8/REST/rest_manager.py') as f:
        file_contents = f.read()

    treeobj = ast.parse(file_contents, 'ipv8/REST/rest_manager.py')

    version_element = None
    for element in treeobj.body:
        if isinstance(element, ast.ClassDef) and element.name == "RESTManager":
            for inner_definition in element.body:
                if isinstance(inner_definition, ast.AsyncFunctionDef) and inner_definition.name == "start":
                    for f_statement in inner_definition.body:
                        if (isinstance(f_statement, ast.Assign)
                                and f_statement.targets
                                and isinstance(f_statement.targets[0], ast.Name)
                                and cast(ast.Name, f_statement.targets[0]).id == "aiohttp_apispec"
                                and isinstance(f_statement.value, ast.Call)
                                and isinstance(f_statement.value.func, ast.Name)
                                and f_statement.value.func.id == "AiohttpApiSpec"):
                            for setup_arg in f_statement.value.keywords:
                                if setup_arg.arg == "version":
                                    version_element = setup_arg.value

    if not version_element:
        print("No 'version' assignment found in ipv8/REST/rest_manager.py")  # noqa: T201
        sys.exit(1)

    return file_contents, cast(ast.Constant, version_element)


def modify_setup(file_contents: str, setup_expression: ast.Expr) -> tuple[str, str, str, str, str]:
    """
    Rewrite the ``setup.py`` contents by modifying the ``setup(...)`` AST node.
    """
    print("[2/8] | Modifying setup.py file")  # noqa: T201
    new_filecontents = ""
    old_version = ""
    old_version_tag = ""
    new_version = ""
    new_version_tag = ""
    for keyword in cast(ast.Call, setup_expression.value).keywords:
        if keyword.arg == "version":
            lineno = keyword.value.lineno
            coloffset = keyword.value.col_offset
            old_version = cast(ast.Name, keyword.value).s
            version = Version(old_version)

            new_vstring = [version.major, version.minor, version.micro]
            old_version_tag = '.'.join(str(s) for s in new_vstring[:2])
            new_vstring[1] += 1
            new_version = '.'.join(str(s) for s in new_vstring)
            new_version_tag = '.'.join(str(s) for s in new_vstring[:2])

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
    print("[2/8] | Modifying doc/conf.py file")  # noqa: T201

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
    print("[2/8] | Modifying ipv8/REST/rest_manager.py file")  # noqa: T201

    new_split_filecontents = file_contents.splitlines(True)

    lineno = element.lineno
    coloffset = element.col_offset
    old_version = element.s

    source_line = new_split_filecontents[lineno - 1]
    new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                          + f"v{new_version_tag}"
                                          + source_line[len(old_version) + coloffset + 1:])

    return "".join(new_split_filecontents)


print("[1/8] Parsing source files.")  # noqa: T201
old_setup_file, setup_ast = parse_setup()
old_docs_file, docs_ast_elements = parse_doc_conf()
old_rest_manager_file, rest_manager_ast = parse_rest_manager()

print("[2/8] Modifying source files")  # noqa: T201
old_version, old_version_tag, new_version, new_version_tag, new_setup_file = modify_setup(old_setup_file, setup_ast)
new_docs_file = modify_docs(old_docs_file, docs_ast_elements, new_version, new_version_tag)
new_rest_manager_file = modify_rest_manager(old_rest_manager_file, rest_manager_ast, new_version_tag)

# LOGIN
print("[3/8] Requesting GitHub username and password")  # noqa: T201

username = input('Username: ')
token = getpass.getpass(prompt='Token (needs public_repo access, no token? visit https://github.com/settings/tokens): ', stream=None)

github = Github(token)

# GET REPOSITORY REFERENCES
print("[4/8] Retrieving Tribler:py-ipv8 and %s:py-ipv8" % username)  # noqa: T201

ipv8_fork_repo = github.get_repo("%s/py-ipv8" % username)

if not ipv8_fork_repo:
    print("Could not find your IPv8 repository! Did you fork?")  # noqa: T201
    sys.exit(1)

ipv8_repo = github.get_repo("Tribler/py-ipv8")

# GET CHANGES
print("[5/8] Calculating changes since last release")  # noqa: T201

known_tags = ipv8_repo.get_tags()
last_release_commit = None
release = ipv8_repo.get_latest_release()
tag_name = release.tag_name
for t in known_tags:
    if t.name == tag_name:
        last_release_commit = t.commit

comparison = ipv8_repo.compare(last_release_commit.sha, "Tribler:master")
commits_since_last = comparison.total_commits + 2

repo_creation = ipv8_repo.created_at
first_commit = ipv8_repo.get_commits(until=repo_creation)[0]
comparison_forever = ipv8_repo.compare(first_commit.sha, last_release_commit.sha)
total_commits = commits_since_last + comparison_forever.total_commits + 1

# REMOVE EXISTING FEATURE BRANCH
print("[6/8] Removing previous branch on fork, if it exists")  # noqa: T201

for branch in ipv8_fork_repo.get_branches():
    if branch.name == "automated_version_update":
        branch_ref = ipv8_fork_repo.get_git_ref('heads/automated_version_update')
        branch_ref.delete()

# CREATE FEATURE BRANCH
print("[7/8] Pushing changes to branch on fork")  # noqa: T201

sb = ipv8_repo.get_branch("master")
git_commit_base = [ipv8_fork_repo.get_git_commit(sb.commit.sha)]

setup_file_tree_element = InputGitTreeElement("setup.py", "100644", "blob", new_setup_file)
docs_file_tree_element = InputGitTreeElement("doc/conf.py", "100644", "blob", new_docs_file)
rest_manager_tree_element = InputGitTreeElement("ipv8/REST/rest_manager.py", "100644", "blob", new_rest_manager_file)

new_tree = ipv8_fork_repo.create_git_tree([setup_file_tree_element, docs_file_tree_element, rest_manager_tree_element],
                                          ipv8_fork_repo.get_git_tree(sb.commit.sha))

new_commit = ipv8_fork_repo.create_git_commit("Automated version increment", new_tree, git_commit_base)
ipv8_fork_repo.create_git_ref(ref='refs/heads/automated_version_update', sha=new_commit.sha)

# CREATE PULL REQUEST
print("[8/8] Creating Pull Request to main repository")  # noqa: T201


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
        for mistake in residual_prefixes:
            if commit_msg.startswith(mistake):
                corrected = residual_prefixes[mistake] + commit_msg[len(mistake):]
        # Second, modify misspellings, e.g. "Add some feature" -> "Added some feature".
        # We do this after the first step to correct compound errors (both leaving the prefix AND not adhering to
        # the naming standard).
        for mistake in misspellings:
            if corrected.startswith(mistake):
                corrected = misspellings[mistake] + corrected[len(mistake):]
        out.append(corrected)
    return sorted(out)


pr = ipv8_repo.create_pull(title="Automated Version Update",
                           body="Suggested release message\n---\n"
                           f"Tag version: {new_version_tag}\n"
                           f"Release title: IPv8 v{new_version_tag}.{total_commits} release\nBody:\n"
                           f"Includes the first {total_commits} commits (+{commits_since_last} since v{old_version_tag}) for IPv8, containing:\n\n - "
                           + ("\n - ".join(commit_messages_to_names([c.commit.message.split('\n')[2]
                                                                     for c in comparison.commits
                                                                     if c.commit.message.startswith('Merge')]))),
                           base='master',
                           head='{}:{}'.format(username, 'automated_version_update'), draft=True)

pr_labels = next(label for label in ipv8_repo.get_labels() if label.name == "automatedpr")
pr.add_to_labels(pr_labels)
