#!/usr/bin/env python3
import argparse
import csv
import glob
import io
import json
import logging
import os
import statistics
from enum import Enum, unique
from typing import Any

import coloredlogs
import yaml
from tabulate import tabulate

try:
    import pybadges

    _has_pybadges = True
except ImportError as e:
    _has_pybadges = False

try:
    import matplotlib.pyplot as plt

    _has_matplotlib = True
except ImportError:
    _has_matplotlib = False

LOG = logging.getLogger()
LOG.setLevel(level=logging.DEBUG)
coloredlogs.install(level="DEBUG", logger=LOG)

ENV = {}


def find_ctf_root_directory() -> str:
    path = os.path.join(os.getcwd(), ".")

    while path != (path := os.path.dirname(p=path)):
        dir = os.listdir(path=path)

        if ".git" not in dir:
            continue
        if "challenges" not in dir:
            continue
        break

    if path == "/":
        if "CTF_ROOT_DIR" not in os.environ:
            LOG.critical(
                msg='Could not automatically find the root directory nor the "CTF_ROOT_DIR" environment variable.'
            )
            exit(1)
        return os.environ.get("CTF_ROOT_DIR", default=".")

    LOG.debug(msg=f"Found root directory: {path}")
    return path


CTF_ROOT_DIRECTORY = find_ctf_root_directory()


@unique
class OutputFormat(Enum):
    JSON = "json"
    CSV = "csv"
    YAML = "yaml"

    def __str__(self) -> str:
        return self.value


def remove_ctf_script_root_directory_from_path(path: str) -> str:
    return os.path.relpath(path=path, start=CTF_ROOT_DIRECTORY)


def get_all_available_tracks() -> set[str]:
    tracks = set()

    for entry in os.listdir(
        path=(challenges_directory := os.path.join(CTF_ROOT_DIRECTORY, "challenges"))
    ):
        if not os.path.isdir(s=os.path.join(challenges_directory, entry)):
            continue

        tracks.add(entry)

    return tracks



def parse_challenge_yaml(path: str) -> dict[str, Any]:
    r = yaml.safe_load(
        stream=open(
            file=(path),
            mode="r",
            encoding="utf-8",
        )
    )

    r["file_location"] = remove_ctf_script_root_directory_from_path(path=path)

    return r



def flags(args: argparse.Namespace) -> None:
    tracks = set()
    for entry in glob.glob(f'{os.path.join(CTF_ROOT_DIRECTORY, "challenges")}/**/challenge*.yml', recursive=True):
        if not args.tracks:
            tracks.add(entry)
        elif entry in args.tracks:
            tracks.add(entry)

    flags = []
    for track in tracks:
        LOG.debug(msg=f"Parsing challenge.yml for challenge {track}")
        challenge_yaml = parse_challenge_yaml(track)

        if not challenge_yaml.get("value"):
            LOG.debug(msg=f"No flag in track {track}. Skipping...")
            continue

        flags.append({'track': track, 'name': challenge_yaml.get('name'), 'value': challenge_yaml.get('value')})

    if not flags:
        LOG.warning(msg="No flag found...")
        return

    if args.format == OutputFormat.JSON:
        print(json.dumps(obj=flags, indent=2))
    elif args.format == OutputFormat.CSV:
        output = io.StringIO()
        writer = csv.DictWriter(f=output, fieldnames=flags[0].keys())
        writer.writeheader()
        writer.writerows(rowdicts=flags)
        print(output.getvalue())
    elif args.format == OutputFormat.YAML:
        print(yaml.safe_dump(data=flags))


def stats(args: argparse.Namespace) -> None:
    LOG.debug(msg="Generating statistics...")
    stats = {}
    challenges = []
    for entry in glob.glob(f'{os.path.join(CTF_ROOT_DIRECTORY, "challenges")}/**/challenge*.yml', recursive=True):
        if not args.tracks:
            challenges.append(entry)
        elif entry in args.tracks:
            challenges.append(entry)

    stats["number_of_challenges"] = len(challenges)
    stats["highest_value_flag"] = 0
    stats["total_flags_value"] = 0
    stats["median_flag_value"] = 0
    stats["mean_flag_value"] = 0
    stats["number_of_files"] = 0
    stats["flag_count_per_value"] = {}
    stats["number_of_challenge_designers"] = 0
    challenge_designers = set()
    flags = []
    stats["number_of_flags"] = len(challenges)
    for path in challenges:
        track_yaml = parse_challenge_yaml(path)
        flag_value = track_yaml.get("value")
        flags.append(flag_value)
        stats["number_of_files"] += len(track_yaml.get("files", []))
        stats["total_flags_value"] += flag_value
        if flag_value > stats["highest_value_flag"]:
            stats["highest_value_flag"] = flag_value
        if flag_value not in stats["flag_count_per_value"]:
            stats["flag_count_per_value"][flag_value] = 0
        stats["flag_count_per_value"][flag_value] += 1
        challenge_designers.add(track_yaml.get('author', '').lower())

    stats["median_flag_value"] = statistics.median(flags)
    stats["mean_flag_value"] = round(statistics.mean(flags), 2)
    stats["number_of_challenge_designers"] = len(challenge_designers)

    # Sort dict keys
    stats["flag_count_per_value"] = {
        key: stats["flag_count_per_value"][key]
        for key in sorted(stats["flag_count_per_value"].keys())
    }

    stats["challenge_designers"] = sorted(list(challenge_designers))

    print(json.dumps(stats, indent=2, ensure_ascii=False))
    if args.generate_badges:
        if not _has_pybadges:
            LOG.critical(msg="Module pybadges was not found.")
            exit(code=1)
        LOG.info(msg="Generating badges...")
        os.makedirs(name=".badges", exist_ok=True)
        write_badge(
            "flag",
            pybadges.badge(left_text="Flags", right_text=str(stats["number_of_flags"])),  # type: ignore
        )
        write_badge(
            "points",
            pybadges.badge(  # type: ignore
                left_text="Points", right_text=str(stats["total_flags_value"])
            ),
        )
        write_badge(
            "files",
            pybadges.badge(  # type: ignore
                left_text="Files",
                right_text=str(stats["number_of_files"]),
            ),
        )
        write_badge(
            "designers",
            pybadges.badge(  # type: ignore
                left_text="Challenge Designers",
                right_text=str(stats["number_of_challenge_designers"]),
            ),
        )

    if args.charts:
        if not _has_matplotlib:
            LOG.critical(msg="Module matplotlib was not found.")
            exit(code=1)
        LOG.info(msg="Generating charts...")
        mpl_logger = logging.getLogger("matplotlib")
        mpl_logger.setLevel(logging.INFO)
        os.makedirs(name=".charts", exist_ok=True)
        # Flag count per value barchart
        plt.bar(
            stats["flag_count_per_value"].keys(), stats["flag_count_per_value"].values()
        )
        plt.xticks(
            ticks=range(0, max(stats["flag_count_per_value"].keys()) + 1), rotation=45
        )
        plt.grid(True, linestyle="--", alpha=0.3)
        plt.xlabel("Flag Value")
        plt.ylabel("Number of Flags")
        plt.title("Number of Flags per Value")
        plt.savefig(os.path.join(".charts", "flags_per_value.png"))
        plt.clf()


    LOG.debug(msg="Done...")


def list_tracks(args: argparse.Namespace) -> None:
    tracks = []
    for track in glob.glob(f'{os.path.join(CTF_ROOT_DIRECTORY, "challenges")}/**/challenge*.yml', recursive=True):
        tracks.append(track)

    parsed_tracks = []
    for track in tracks:
        parsed_track = parse_challenge_yaml(track)

        # find the discourse topic name
        topic = None
        parsed_tracks.append(
            [
                parsed_track["name"],
                parsed_track["author"],
                parsed_track["value"],
                parsed_track["category"],
            ]
        )

    if args.format == "pretty":
        LOG.info(
            "\n"
            + tabulate(
                parsed_tracks,
                headers=[
                    "Challenge name",
                    "Author",
                    "Value",
                    "Category",
                ],
                tablefmt="fancy_grid",
            )
        )
    else:
        raise ValueError(f"Invalid format: {args.format}")


def write_badge(name: str, svg: str) -> None:
    with open(
        file=os.path.join(".badges", f"badge-{name}.svg"), mode="w", encoding="utf-8"
    ) as f:
        f.write(svg)


def main():
    # Command line parsing.
    parser = argparse.ArgumentParser(
        prog="ctf",
        description="CTF preparation tool. Run from the root CTF repo directory or set the CTF_ROOT_DIR environment variable to run the tool.",
    )

    subparsers = parser.add_subparsers(required=True)

    parser_flags = subparsers.add_parser(
        "flags",
        help="Get flags from tracks",
    )
    parser_flags.set_defaults(func=flags)
    parser_flags.add_argument(
        "--tracks",
        "-t",
        nargs="+",
        default=[],
        help="Only flags from the given tracks (use the folder name)",
    )
    parser_flags.add_argument(
        "--format",
        help="Output format.",
        choices=list(OutputFormat),
        default=OutputFormat.JSON,
        type=OutputFormat,
    )

    parser_stats = subparsers.add_parser(
        "stats",
        help="Generate statistics (such as number of tracks, number of flags, total flag value, etc.) from all the `track.yaml files. Outputs as JSON.",
    )
    parser_stats.set_defaults(func=stats)
    parser_stats.add_argument(
        "--tracks",
        "-t",
        nargs="+",
        default=[],
        help="Name of the tracks to count in statistics (if not specified, all tracks are counted).",
    )
    parser_stats.add_argument(
        "--generate-badges",
        action="store_true",
        default=False,
        help="Generate SVG files of some statistics in the .badges directory.",
    )
    parser_stats.add_argument(
        "--charts",
        action="store_true",
        default=False,
        help="Generate PNG charts of some statistics in the .charts directory.",
    )

    parser_stats.add_argument(
        "--historical",
        action="store_true",
        default=False,
        help="Use in conjunction with --charts to generate historical data. ONLY USE THIS IF YOU KNOW WHAT YOU ARE DOING. THIS IS BAD CODE THAT WILL FUCK YOUR REPO IN UNEXPECTED WAYS.",
    )

    parser_list = subparsers.add_parser(
        "list",
        help="List tracks and their author(s).",
    )
    parser_list.set_defaults(func=list_tracks)
    parser_list.add_argument(
        "--format",
        "-f",
        choices=["pretty"],
        default="pretty",
        help="Output format.",
    )

    args = parser.parse_args()

    for k, v in os.environ.items():
        ENV[k] = v


    if not os.path.isdir(s=(p := os.path.join(CTF_ROOT_DIRECTORY, "challenges"))):
        LOG.error(
            msg=f"Directory `{p}` not found. Make sure this script is ran from the root directory OR set the CTF_ROOT_DIR environment variable to the root directory."
        )
        exit(code=1)

    args.func(args=args)


if __name__ == "__main__":
    main()
