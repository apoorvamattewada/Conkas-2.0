import sys
import argparse
from z3 import *
from solcx import compile_files
from solcx import install_solc, set_solc_version


# Function to parse the AST
from solcx import install_solc, set_solc_version

install_solc('0.4.25')
set_solc_version('0.4.25')


def parse_ast_node(node, vulnerabilities, function_name=None):
    if node['nodeType'] == 'FunctionDefinition':
        function_name = node['name']

    if node['nodeType'] == 'BinaryOperation':
        if node['operator'] == '*':
            left = node['left']
            right = node['right']

            if (left['nodeType'] == 'Identifier' and left['name'] == 'msg.value') or (right['nodeType'] == 'Identifier' and right['name'] == 'msg.value'):
                vulnerabilities.append((function_name, node['src']))

    if 'nodes' in node:
        for child in node['nodes']:
            parse_ast_node(child, vulnerabilities, function_name)

# Function to analyze the Solidity contract


def find_short_address_vulnerabilities(sol_source):
    with open("temp_contract.sol", "w") as temp_file:
        temp_file.write(sol_source)

    output = compile_files(["temp_contract.sol"], output_values=[
                           "ast"], allow_paths=".")

    ast = output['temp_contract.sol']['ast']
    vulnerabilities = []
    parse_ast_node(ast, vulnerabilities)
    return vulnerabilities

# Function to get line number from character position


def get_line_number(sol_source, pos):
    return sol_source.count('\n', 0, pos) + 1

# Function to check vulnerabilities using Z3


def analyze_vulnerabilities(solidity_code):
    vulnerabilities = find_short_address_vulnerabilities(solidity_code)
    s = Solver()

    # Declare address and value variables
    addr = BitVec('addr', 160)
    value = BitVec('value', 256)

    # Set the address to be non-zero
    s.add(addr != 0)

    # Create a list to store potential vulnerable inputs
    vulnerable_inputs = []

    for function_name, vulnerability in vulnerabilities:
        start, length, _ = map(int, vulnerability.split(':'))
        # <-- changed to `solidity_code`
        vulnerable_expression = solidity_code[start:start + length]
        # <-- changed to `solidity_code`
        line_number = get_line_number(solidity_code, start)

        if "* 1 ether" in vulnerable_expression:
            s.push()
            s.add(Extract(7, 0, Concat(addr, value)
                  [:-1 * 8]) == BitVecVal(0x80, 8))
            if s.check() == sat:
                model = s.model()
                vulnerable_addr = model[addr].as_long()
                vulnerable_value = model[value].as_long()
                vulnerable_inputs.append(
                    (function_name, line_number, hex(vulnerable_addr), hex(vulnerable_value)))
                print("Short Address vulnerability found. Maybe in function: '{}'. Line number: {}.".format(
                    function_name, line_number))
            s.pop()

    if vulnerable_inputs:
        result = "Vulnerability details: {}".format(vulnerable_inputs)
        return result
    return None


def main():
    parser = argparse.ArgumentParser(
        description='Analyze a Solidity file for short address vulnerabilities')
    parser.add_argument('--find-all-vulnerabilities', action='store_true',
                        help='Find all vulnerabilities (currently only short address vulnerabilities are supported)')
    parser.add_argument('-s', '--solidity-file', required=True,
                        help='Path to the Solidity file')

    args = parser.parse_args()

    if args.find_all_vulnerabilities:
        with open(args.solidity_file, 'r') as f:
            solidity_code = f.read()

        vulnerable_inputs = analyze_vulnerabilities(solidity_code)
        if vulnerable_inputs:
            print("Vulnerability details: {}".format(vulnerable_inputs))
    else:
        print("No analysis option specified. Use --find-all-vulnerabilities to analyze the Solidity file for short address vulnerabilities.")
        sys.exit(1)


if __name__ == "__main__":
    main()
