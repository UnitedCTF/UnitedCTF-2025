#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pyyaml",
# ]
# ///

"""
This script validates challenge YAML files in the "challenges" directory for UnitedCTF2025.
It checks for correct structure, required fields, and Docker image existence for each deployed challenge.
Run `docker login ghcr.io` before executing this script to ensure private images can be checked.
"""

from pathlib import Path
import yaml
import subprocess


def find_challenge_yml_files(challenges_dir: Path):
    # Find all challenge.yml and challenge-*.yml files recursively
    yml_files = list(challenges_dir.rglob("challenge*.yml"))
    return yml_files


def check_docker_image(image: str) -> tuple[bool, str | None]:
    try:
        subprocess.run(
            ["docker", "manifest", "inspect", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            text=True,
        )
        return True, None
    except subprocess.CalledProcessError:
        return False, f"Docker image '{image}' does not exist."


def check_challenge_yml(file_path: Path) -> tuple[bool, str | None]:
    with open(file_path, "r") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            return False, f"YAML error: {e}"

    if data.get("type") == "ansible":
        if "playbook_name" not in data:
            return False, "'playbook_name' is missing for ansible challenge."

        if "image" not in data:
            return False, "'image' is missing for ansible challenge."

        is_valid, message = check_docker_image(data["image"])
        if not is_valid:
            return False, message

        if data.get("connection_info"):
            return False, "'connection_info' should not be used."

        if data["playbook_name"] == "dynamic_http":
            if (
                "deploy_parameters" not in data
                or "chall_name" not in data["deploy_parameters"]
            ):
                return False, "'chall_name' is required in 'deploy_parameters' for 'dynamic_http' playbook."

        elif data["playbook_name"] == "tcp":
            if (
                "deploy_parameters" not in data
                or "chall_name" not in data["deploy_parameters"]
                or "published_ports" not in data["deploy_parameters"]
            ):
                return False, "'chall_name' and 'published_ports' are required in 'deploy_parameters' for 'tcp' playbook."

        else:
            return False, f"Unknown playbook_name '{data['playbook_name']}'."

    elif "image" in data:
        is_valid, message = check_docker_image(data["image"])
        if not is_valid:
            return False, message

        if "playbook_name" not in data:
            return False, "'playbook_name' is missing for challenge with 'image'."

        if data["playbook_name"] == "dynamic_http":
            if (
                "deploy_parameters" not in data
                or "chall_name" not in data["deploy_parameters"]
            ):
                return False, "'chall_name' is required in 'deploy_parameters' for 'dynamic_http' playbook."

        elif data["playbook_name"] == "tcp":
            if (
                "deploy_parameters" not in data
                or "chall_name" not in data["deploy_parameters"]
                or "published_ports" not in data["deploy_parameters"]
            ):
                return False, "'chall_name' and 'published_ports' are required in 'deploy_parameters' for 'tcp' playbook."

        elif data["playbook_name"] == "custom_compose":
            if (
                "deploy_parameters" not in data
                or "compose_definition" not in data["deploy_parameters"]
            ):
                return False, "'compose_definition' is required in 'deploy_parameters' for 'custom_compose' playbook."

    return True, None


def main():
    challenges_dir = Path("challenges")
    yml_files = find_challenge_yml_files(challenges_dir)
    for f in yml_files:
        is_valid, message = check_challenge_yml(f)
        if not is_valid:
            print(f"Invalid: {f} - {message}")


if __name__ == "__main__":
    main()
