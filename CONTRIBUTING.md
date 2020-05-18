It's great that you want to contribute to IPv8. We would like you to take heed of the following guidelines though, based on your situation:

### I have found a bug in IPv8

 1. Check that nobody else is working on your issue by checking the GitHub issue tracker and looking at the open Pull Requests.
 2. If nobody has encountered your issue, please open an issue on the GitHub issue tracker. Try to mention as many details as possible so we can reproduce your issue.
 3. If you have a (non-trivial) suggested fix, please mention this in the issue. We will discuss it there with you.

### I want a feature in IPv8

 1. Check that nobody else has suggested your feature by checking both the open and closed issues. You may find certain features have been suggested and worked on in the past, but rejected for some reason or other.
 2. If nobody has suggested your feature, please open an issue on the GitHub issue tracker.
 3. If you have a (non-trivial) suggested implementation, please mention it in the issue. We will discuss it there with you. Images are appreciated for larger changes.
 
### I want to open a Pull Request

 1. Make a feature branch on your own fork of IPv8 to work on your feature.
 2. We accept Pull Requests that are tied to issues or change a very small amount of lines. If you forget to open an issue with your Pull Request, the discussion will take place in the Pull Request - often leading to a very unstructured discussion. Contributions to the documentation are exempt from this rule, as they are quite literally self-documenting.
 3. It is better to make small changes than large ones, as smaller changes usually have less bugs.
 4. Make sure the automatic Pull Request tests pass or rationalize why it is O.K. that they do not.
 5. When you deem it done, clearly mark your Pull Request as ready for review (prefix it with `READY:` for example) or ask an administrator to review your Pull Request.
 
### I have administrator rights

Only use them in the following situations:

 1. Tagging open and opened issues in the GitHub issue tracker.
 2. Reviewing Pull Requests.
 3. Allow testing of Pull Requests (type `ok to test` as a comment in the Pull Request).
 4. Merging Pull Requests, but only if the automated tests pass (or failure is properly ratified) and **all** reviewers are sufficiently satisfied with the change. **Never ever merge your own Pull Request** without approving reviews from others.
 5. Making a new branch on the main repository for **completed** changes that conflict with -or cannot be merged into- the `master` branch, but should not be lost. Feature branches that are still in development should not be in the main repository. 
 6. Authoring releases. Make sure the version is incremented in `setup.py` (for which you can use `github_increment_version.py` in most cases) before authoring a release on GitHub. Next, create a release on PyPi with `python3 setup.py sdist bdist_wheel` and `python3 -m twine upload dist/*`.

### Common Q&A

**Q:** _Do I need a new dependency?_<br>
\ **A:** Probably not. On the off chance that you actually do (and an administrator agrees), don't forget to edit the `requirements.txt` and the `setup.py` files.

**Q:** _Do I need a development/feature branch on the main repository?_<br>
\ **A:** No. GitHub stops automatically closing issues and pulling the repository will be slower, send irrelevant code to other developers and permanently inflate the repository's size. Use a feature branch on your own fork. 

**Q:** _Do I need a major overhaul of (part of) the core protocol?_<br>
\ **A:** Either start a different project or incrementally introduce your change if you do. Make sure to thoroughly motivate your changes.
