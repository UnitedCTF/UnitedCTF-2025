#!/bin/bash

HELP_MESSAGE="""Usage: $0 --org <organization> --path_bundle <path>

Options:
  --org, -o              The organization where the challenges will be.
  --path_bundle, -p      The path to the challenge repository bundle containing all workflows.
  --help, -h             Show this help message.
"""

if [[ "$#" -eq 0 ]]; then
  echo -e "$HELP_MESSAGE"
  exit 0
fi

while [[ "$#" -gt 0 ]]; do
  case $1 in
    --org|-o) ORGANIZATION="$2"; shift ;;
    --path_bundle|-p) PATH_CHALL="$2"; shift ;;
    --help|-h)
      echo -e "$HELP_MESSAGE"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

if [[ -z "$ORGANIZATION" || -z "$PATH_CHALL" ]]; then
  echo "Error: Missing required arguments."
  echo -e "$HELP_MESSAGE"
  exit 1
fi

# Create a template repository
echo "Creating template repository in organization '$ORGANIZATION'..."
if [[ ! -f "$PATH_CHALL" ]]; then
  echo "Error: Path '$PATH_CHALL' does not exist."
  exit 1
fi

# Prompt for repository settings
echo -e "\nPlease configure the following settings manually:"
echo "1. Set the default token to Read-only permissions."
echo "2. Enable fork pull request workflows in private repositories."
echo "3. Require approval for running fork pull request workflows from first-time contributors who are new to GitHub."
echo "4. Enable: Allow forking of private repositories."

SETTING_URL="https://github.com/organizations/$ORGANIZATION/settings/actions"
xdg-open "$SETTING_URL" 2>/dev/null || open "$SETTING_URL" 2>/dev/null || echo "Please open the URL manually."

TEMPLATE="https://github.com/$ORGANIZATION/chall/settings"
xdg-open "$TEMPLATE" 2>/dev/null || open "$SETTING_URL" 2>/dev/null || echo "Please open the URL manually."

# Generate PR_WRITE_PAT
echo -e "\nGenerating PR_WRITE_PAT..."
TOKEN_URL="https://github.com/settings/personal-access-tokens/new?name=pr-write&target_name=$ORGANIZATION&expires_in=30&pull_requests=write&contents=read"
echo "Visit the following URL to generate the token and keep the value for later. You will need to approve the token as an admin: $TOKEN_URL"
xdg-open "$TOKEN_URL" 2>/dev/null || open "$TOKEN_URL" 2>/dev/null || echo "Please open the URL manually."

echo -e "\nSetup complete. Follow the instructions to finalize the configuration."