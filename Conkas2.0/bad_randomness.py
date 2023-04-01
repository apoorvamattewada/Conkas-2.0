import re
import sys
import argparse


def bad_randomness_analyse(file_path: str, find_all_vulnerabilities: bool):
    # Open the Solidity file and read its contents
    with open(file_path, 'r') as f:
        solidity_code = f.read()

    # Define the regular expression patterns to search for
    patterns = {
        'block.timestamp': r'\b(block\.timestamp\b)',
        'now': r'\bnow\b',
        'block.difficulty': r'\b(block\.difficulty\b)',
        'block.number': r'\b(block\.number\b)',
        'blockhash': r'\b(blockhash\b)',
        'block.coinbase': r'\b(block\.coinbase\b)',
    }

    # Iterate through the patterns and search for them in the Solidity code
    for pattern_name, pattern_regex in patterns.items():
        matches = re.finditer(pattern_regex, solidity_code)

        # Print out the line numbers and pattern type of the matches
        for match in matches:
            line_number = solidity_code.count('\n', 0, match.start()) + 1
            print(
                f"Found bad randomness pattern '{pattern_name}' at line {line_number}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze a Solidity file for bad randomness patterns')
    parser.add_argument('--find-all-vulnerabilities', action='store_true',
                        help='Find all vulnerabilities (currently only bad randomness patterns are supported)')
    parser.add_argument('-s', '--solidity-file', required=True,
                        help='Path to the Solidity file')

    args = parser.parse_args()

    if args.find_all_vulnerabilities:
        bad_randomness_analyse(args.solidity_file,
                               find_all_vulnerabilities=True)
    else:
        print("No analysis option specified. Use --find-all-vulnerabilities to analyze the Solidity file for bad randomness patterns.")
        sys.exit(1)


if __name__ == "__main__":
    main()
