import argparse
import subprocess
from collections import defaultdict
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Generate SHA-256 and MD5 checksum files for files in given directory"
)

IGNORE = (".sha256", "sha-256", ".md5", "md-5")


def collect_dir_files(directory: Path) -> set[Path]:
    files = set()

    for item in directory.iterdir():
        if item.suffix.lower() not in IGNORE:
            files.add(directory / item)

    print(f"Collected {len(files)} files.")

    return files


def generate_sha256(
    files: set | tuple | list,
) -> tuple[list[tuple[str, str]], set[Path]]:
    """
    Generates SHA256 hash file for each given files.

    Returns a tuple where the first element is a list of tuples, where
    the first element of the tuple is the file_name the hash pertains to
    and the second element of the tuple is the hash of the filename.

    The second element of the return tuple is a set of paths of the generated
    hash file paths.

    :return: A tuple containing a list of file name and hash tuple and a set of
    file paths representing the generated hash files.
    """

    print("Generating SHA-256 Hashes")
    written = list()
    generated = set()

    for file in files:
        output_file_name = f"{file.name}.sha256"
        output_file = file.parent / output_file_name
        command = ["sha256sum", str(file)]

        with open(output_file, "w") as out_f:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            out_f.write(result.stdout)

            if result.returncode != 0:
                print(f"Error processing {file}: {result.stderr}")
            else:
                print(f"* Generated SHA-256 hash for file {file.name} ({str(file)})")
                # Split at space, get leftmost result
                written.append((file, result.stdout.split(" ")[0]))

            generated.add(output_file)

    return written, generated


def generate_md5(files: set | tuple | list) -> tuple[list[tuple[str, str]], set[Path]]:
    """
    Generates MD5 hash file for each given files.

    Returns a tuple where the first element is a list of tuples, where
    the first element of the tuple is the file_name the hash pertains to
    and the second element of the tuple is the hash of the filename.

    The second element of the return tuple is a set of paths of the generated
    hash file paths.

    :return: A tuple containing a list of file name and hash tuple and a set of
    file paths representing the generated hash files.
    """

    print("Generating MD5 Hashes")
    written = list()
    generated = set()

    for file in files:
        output_file_name = f"{file.name}.md5"
        output_file = file.parent / output_file_name
        command = ["md5sum", str(file)]

        with open(output_file, "w") as out_f:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            out_f.write(result.stdout)

            if result.returncode != 0:
                print(f"Error processing {file}: {result.stderr}")
            else:
                print(f"* Generated MD5 hash for file {file.name} ({str(file)})")
                # Split at space, get leftmost result
                written.append((file, result.stdout.split(" ")[0]))

            generated.add(output_file)

    return written, generated


def generate_table(combos, headers: list[str], small_font=False) -> str:
    """
    Generates a well-aligned Markdown table from a list of hash results.

    :param combos: A list of lists containing tuples (filename, hash).
    :param headers: List of column headers (e.g., ["File", "SHA256", "MD5"]).
    :return: A string containing the formatted Markdown table.
    """

    # We'll map filenames to hash values
    hash_map = defaultdict(list)

    for combo_results in combos:
        for filepath, hash_value in combo_results:
            hash_map[filepath.name].append(hash_value)

    # Ensure all entries have the correct number of columns
    num_hashes = len(combos)
    for file in hash_map:
        while len(hash_map[file]) < num_hashes:
            hash_map[file].append("N/A")

    sorted_files = sorted(hash_map.keys())

    # Small for formatting to hash values
    def format_hash(value):
        if small_font:
            return f"<sub><sup>{value}</sup></sub>"
        return value

    # Calculate column widths
    col_widths = []
    num_columns = len(headers)

    for i in range(num_columns):
        max_width = len(headers[i])  # Start with header width

        # Check for max length of entries in each column
        for file in sorted_files:
            entry = (
                file if i == 0 else format_hash(hash_map[file][i - 1])
            )  # First column is filename
            max_width = max(max_width, len(entry))

        col_widths.append(max_width)

    # Helper function to format a row properly
    def format_row(row):
        return (
            "| "
            + " | ".join(f"{cell:<{col_widths[i]}}" for i, cell in enumerate(row))
            + " |"
        )

    # Build markdown table
    table = []
    table.append(format_row(headers))  # Header row
    table.append(
        "|-" + "-|-".join("-" * col_widths[i] for i in range(num_columns)) + "-|"
    )  # Separator row

    # Fill rows
    for file in sorted_files:
        row = [file] + [format_hash(hash_value) for hash_value in hash_map[file]]
        table.append(format_row(row))

    return "\n".join(table)


def parse_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
    # Root Directory
    parser.add_argument(
        "root_dir",
        type=Path,
        default=Path.cwd(),
        nargs="?",
        help="Path to the system location (default: current working directory).",
    )
    # No Keep Files
    parser.add_argument(
        "--no-keep-files",
        "-nkf",
        action="store_true",
        default=False,
        help="Delete generated hash files after run.",
    )
    # Print Table
    parser.add_argument(
        "--table",
        "-t",
        action="store_true",
        default=False,
        help="Print output table where headers are Files, SHA256 and MD5.",
    )
    # <sub><sup>
    parser.add_argument(
        "--subsup",
        "-ss",
        action="store_true",
        default=False,
        help="Encapsulate row results (exclude header column) in <sub><sup>WORD</sup></sub> tag for smaller font",
    )

    args = parser.parse_args()

    return args


def main():
    args = parse_args(parser)
    print(f"Generate SHA-256 and MD5 checksums for files in '{args.root_dir}'")

    root = args.root_dir
    no_keep_files = args.no_keep_files
    print_table = args.table
    arg_subsup = args.subsup

    if not root or not Path(root).exists():
        print(f"Invalid path '{root}'")
        return False

    root = Path(root)

    if not root.is_dir():
        print(f"[DEBUG] Root is not dir. Getting current parent structure.")
        root = root.parent

    files_to_process = collect_dir_files(root)

    funcs = (generate_sha256, generate_md5)
    # List of func return combos, typically a list containing a tuple of (filepath, hash)
    combos = list()
    all_generated_files = set()
    print()
    for func in funcs:
        combo_file_hash, generated_files = func(files_to_process)
        combos.append(combo_file_hash)
        all_generated_files.update(generated_files)
        print("")  # Spacer

    if no_keep_files:
        print("Delete generated hash files [--no-keep-files]")
        for filepath in all_generated_files:
            if not filepath.exists():
                print(f"* Missing {filepath}")
                continue

            print(f"* Delete {filepath}")
            # Future consideration: https://pypi.org/project/Send2Trash/
            filepath.unlink(missing_ok=True)
        print()

    if print_table:
        print(f"Generated table [--table{', --subsup' if arg_subsup else ''}]")
        table = generate_table(combos, ["File", "SHA256", "MD5"], small_font=arg_subsup)
        print(table)
        print()

    print("Finished.")


if __name__ == "__main__":
    main()
