"""
This script automatically increments the IPv8 setup.py version and creates a PR for it on GitHub.
The suggested release message is used as the PR body.

This script requires the additional dependency PyGithub.
"""
import ast
import getpass
import sys
from distutils.version import LooseVersion

from github import Github


# MAKE SETUP.PY CHANGES
print("[1/8] Parsing setup.py file")

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

print("[2/8] Modifying setup.py file")
new_filecontents = ""
old_version = ""
old_version_tag = ""
new_version = ""
new_version_tag = ""
for keyword in setup_expression.value.keywords:
    if keyword.arg == "version":
        lineno = keyword.value.lineno
        coloffset = keyword.value.col_offset
        old_version = keyword.value.s
        version = LooseVersion(old_version)

        new_vstring = version.version
        old_version_tag = '.'.join(str(s) for s in new_vstring[:2])
        new_vstring[1] += 1
        new_version = '.'.join(str(s) for s in new_vstring)
        new_version_tag = '.'.join(str(s) for s in new_vstring[:2])

        new_split_filecontents = filecontents.splitlines(True)
        source_line = new_split_filecontents[lineno - 1]
        new_split_filecontents[lineno - 1] = (source_line[:coloffset + 1]
                                              + new_version
                                              + source_line[len(old_version) + coloffset + 1:])
        new_filecontents = "".join(new_split_filecontents)
        break

# LOGIN
print("[3/8] Requesting GitHub username and password")

username = input('Username: ')
password = getpass.getpass(prompt='Password: ', stream=None)

github = Github(username, password)

# GET REPOSITORY REFERENCES
print("[4/8] Retrieving Tribler:py-ipv8 and %s:py-ipv8" % username)

ipv8_fork_repo = github.get_repo("%s/py-ipv8" % username)

if not ipv8_fork_repo:
    print("Could not find your IPv8 repository! Did you fork?")
    sys.exit(1)

ipv8_repo = github.get_repo("Tribler/py-ipv8")

# GET CHANGES
print("[5/8] Calculating changes since last release")

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
print("[6/8] Removing previous branch on fork, if it exists")

for branch in ipv8_fork_repo.get_branches():
    if branch.name == "automated_version_update":
        branch_ref = ipv8_fork_repo.get_git_ref('heads/automated_version_update')
        branch_ref.delete()

# CREATE FEATURE BRANCH
print("[7/8] Pushing changes to branch on fork")

sb = ipv8_repo.get_branch("master")
ipv8_fork_repo.create_git_ref(ref='refs/heads/automated_version_update', sha=sb.commit.sha)

contents = ipv8_fork_repo.get_contents("setup.py", ref='refs/heads/automated_version_update')
ipv8_fork_repo.update_file(contents.path, "Automated version increment", new_filecontents, contents.sha,
                           branch="automated_version_update")

# CREATE PULL REQUEST
print("[8/8] Creating Pull Request to main repository")

pr = ipv8_repo.create_pull("Automated Version Update",
                           "Suggested release message\n"
                           + "---\n"
                           + ("Tag version: %s\n" % new_version_tag)
                           + ("Release title: IPv8 v%s.%d release\n" % (new_version_tag, total_commits))
                           + ("Body:\n")
                           + ("Includes the first %d commits (+%d since v%s) for IPv8, containing:\n" %
                              (total_commits, commits_since_last, old_version_tag))
                           + ("\n - ")
                           + ("\n - ".join([c.commit.message.split('\n')[2]
                                            for c in comparison.commits if c.commit.message.startswith('Merge')])),
                           'master',
                           '{}:{}'.format(username, 'automated_version_update'), True)

pr_labels = [l for l in ipv8_repo.get_labels() if l.name == "automatedpr"][0]
pr.add_to_labels(pr_labels)
