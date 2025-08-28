import csv
import json
import re
import sys
import os

def is_standalone_pii(key, value):
    """
    Checks if a data point is a standalone PII.
    """
    # Check if the value is a string and not None to prevent errors
    if not isinstance(value, str) or not value:
        return False
        
    pii_types = {
        'phone': re.compile(r'^\d{10}$'),
        'contact': re.compile(r'^\d{10}$'),
        'aadhar': re.compile(r'^\d{12}$'),
        'passport': re.compile(r'^P[A-Z0-9]{7,8}$|^[A-Z]{1,2}\d{7,8}$'),
        'upi_id': re.compile(r'^[a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+$'),
    }

    if key in pii_types and re.match(pii_types[key], value):
        return True
    return False

def is_combinatorial_pii(record):
    """
    Checks if a record contains at least two combinatorial PII data points.
    """
    # Check for full name first
    has_full_name = ('first_name' in record and 'last_name' in record) or 'name' in record
    
    pii_count = 0
    if has_full_name:
        pii_count += 1
    
    # Check for other combinatorial PII keys
    for key in ['email', 'address', 'ip_address', 'device_id']:
        if key in record and record[key]: # Ensure the value is not empty
            pii_count += 1
            
    return pii_count >= 2

def redact_data(key, value):
    """
    Redacts or masks PII data based on its type.
    """
    # Simple redaction for most PII
    if key in ['name', 'address', 'email', 'ip_address', 'aadhar', 'passport', 'upi_id', 'device_id', 'first_name', 'last_name']:
        return "[REDACTED_PII]"
    
    # Masking for phone numbers
    if key in ['phone', 'contact']:
        if isinstance(value, str) and len(value) == 10 and value.isdigit():
            return f"{value[:2]}XXXXX{value[-3:]}"
    
    return value

def process_csv(input_file, output_file):
    """
    Reads the input CSV, detects and redacts PII, and writes to a new CSV.
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    with open(input_file, mode='r', encoding='utf-8') as infile, \
         open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        
        # Write the new header
        writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
        
        # Skip the header row
        try:
            header = next(reader)
        except StopIteration:
            # Handle empty file case
            return

        for row in reader:
            record_id = row[0]
            data_json_str = row[1]
            
            try:
                # Load the JSON data from the second column
                data = json.loads(data_json_str)
                original_record = data.copy()
            except (json.JSONDecodeError, IndexError):
                # Handle malformed JSON or rows with missing data
                writer.writerow([record_id, data_json_str, 'False'])
                continue
                
            is_pii = False
            
            # Check for standalone PII
            for key, value in original_record.items():
                if is_standalone_pii(key, value):
                    is_pii = True
                    break
            
            # If no standalone PII found, check for combinatorial PII
            if not is_pii:
                is_pii = is_combinatorial_pii(original_record)
            
            redacted_data = original_record.copy()
            if is_pii:
                for key, value in original_record.items():
                    # Only redact if it's a known PII field
                    if key in ['name', 'email', 'address', 'ip_address', 'device_id', 'first_name', 'last_name', 'phone', 'contact', 'aadhar', 'passport', 'upi_id']:
                        redacted_data[key] = redact_data(key, value)
            
            # Convert the final dictionary back to a JSON string
            redacted_json_str = json.dumps(redacted_data)
            
            writer.writerow([record_id, redacted_json_str, str(is_pii)])
            
if __name__ == '__main__':
    # The script expects the input file path as a command-line argument.
    # This is more flexible and is the standard way to run this type of script.
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py <input_file.csv>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    # The output filename is hardcoded as per the prompt's naming convention
    output_file = 'redacted_output_candidate_full_name.csv'
    
    process_csv(input_file, output_file)
