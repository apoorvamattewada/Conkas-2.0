import re

def find_bad_randomness(code):
    # Look for any calls to the "blockhash" function.
    blockhash_calls = re.findall(r'blockhash\s*\(\s*(.*?)\s*\)', code)
    
    for call in blockhash_calls:
        # If "blockhash" is invoked with a constant value,
        # For the block hash, it doesn't use a random source.
        if call.isnumeric():
            return True
        # When the "blockhash" function is used with a variable or expression, the block hash is generated randomly.
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', call):
            return False
        
    # There is no randomness to verify if "blockhash" is not called so it return none.
    return None
