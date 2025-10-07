#!/bin/bash

HELP_MESSAGE="Usage: $0 --org <organization> --repo <repo> --bundle <bundle_path> --username <username> --action <action> -f <flag> [-f <flag>...] [--pat <pat>]

Options:
  --org, -o              The organization where the challenges are.
  --repo, -r             The repository base name to be created.
  --bundle, -b           The git bundle to base the repository on.
  --username, -u         The github username to create the challenge for.
  --action, -a           The action to execute. (create, delete)
  --flag, -f             A flag to set as a secret, in NAME=VALUE format. Can be specified multiple times.
  --help, -h             Show this help message.
"

if [[ "$#" -eq 0 ]]; then
  echo -e "$HELP_MESSAGE"
  exit 0
fi


FLAGS=()
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --org|-o) ORGANIZATION="$2"; shift ;;
    --repo|-r) CHALLENGE_REPO="$2"; shift ;;
    --bundle|-b) BUNDLE_PATH="$2"; shift ;;
    --username|-u) USERNAME="$2"; shift ;;
    --flag|-f) FLAGS+=("$2"); shift ;;
    --action|-a) ACTION="$2"; shift ;;
    --help|-h)
      echo -e "$HELP_MESSAGE"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

if [ -z "$ORGANIZATION" ]; then
  echo "Error: --org is required."
  exit 1
fi

if [ -z "$CHALLENGE_REPO" ]; then
  echo "Error: --challenge-repo is required."
  exit 1
fi

if [ -z "$USERNAME" ]; then
  echo "Error: --username is required."
  exit 1
fi

if [ -z "$ACTION" ]; then
  echo "Error: --action is required."
  exit 1
fi

if ! gh api "/users/$USERNAME" --silent; then
  echo "Error: GitHub user '$USERNAME' does not exist."
  exit 1
fi

REPO_NAME="$CHALLENGE_REPO-$USERNAME"

case "$ACTION" in
  create)
    if [ -z "$BUNDLE_PATH" ]; then
      echo "Error: No --bundle has been provided."
      exit 1
    fi

    if [ ! -f "$BUNDLE_PATH" ]; then
      echo "Error: The bundle provided doesn't exists."
      exit 1
    fi

    if [ ${#FLAGS[@]} -eq 0 ]; then
      echo "Warning: No --flag has been provided."
    fi

    echo "Creating challenge for $USERNAME from template $CHALLENGE_REPO..."
    if gh repo view "$ORGANIZATION/$REPO_NAME" >/dev/null 2>&1; then
        echo "Error: Repository $ORGANIZATION/$REPO_NAME already exists."
        exit 1
    fi

    gh repo create "$ORGANIZATION/$REPO_NAME" \
      --private \
      --description "Challenge for $USERNAME based on $CHALLENGE_REPO" \

    if [ ! $? ]; then
        echo "Failed to create repository $ORGANIZATION/$REPO_NAME."
        exit 1
    fi

    temp_dir=$(mktemp -d)
    git clone --bare "$BUNDLE_PATH" "$temp_dir"
    cd "$temp_dir" || exit
    git remote set-url origin "https://x-oauth-basic:$GH_TOKEN@github.com/$ORGANIZATION/$REPO_NAME.git"
    git push --mirror origin


    echo "Adding $USERNAME as a collaborator with read permissions..."
    gh api --method PUT "/repos/$ORGANIZATION/$REPO_NAME/collaborators/$USERNAME" -f 'permission=read' >/dev/null 2>&1

    if [ ! $? ]; then
        echo "Failed to add $USERNAME as a collaborator."
        gh repo delete "$ORGANIZATION/$REPO_NAME" --yes
        exit 1
    fi

    for flag_pair in "${FLAGS[@]}"; do
      if [[ "$flag_pair" != *"="* ]]; then
        echo "Error: Invalid flag format for '$flag_pair'. Use NAME=VALUE." >&2
        exit 1
      fi
      flag_name="${flag_pair%%=*}"
      flag_value="${flag_pair#*=}"
      gh secret set "$flag_name" --body "$flag_value" -R "$ORGANIZATION/$REPO_NAME"
    done

    echo "Challenge repository created: https://github.com/$ORGANIZATION/$REPO_NAME"
    ;;

  delete)
    echo "Deleting challenge repository for $USERNAME..."
    if ! gh repo view "$ORGANIZATION/$REPO_NAME" >/dev/null 2>&1; then
        echo "Repository $ORGANIZATION/$REPO_NAME does not exist. Nothing to delete."
        exit 1
    fi
    gh repo delete "$ORGANIZATION/$REPO_NAME" --yes

    if [ ! $? ] ; then
        echo "Failed to delete repository $ORGANIZATION/$REPO_NAME."
        exit 1
    fi

    echo "Challenge repository deleted successfully."
    ;;

  *)
    echo "Error: Invalid action '$ACTION'. Allowed actions are 'create' or 'delete'."
    exit 1
    ;;
esac
