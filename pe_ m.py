import subprocess

def classify_pe_file(pe_file_path):
    result = subprocess.run(['python', 'pe_classifier.py', pe_file_path], capture_output=True, text=True)
    print(result.stdout)

# Example usage
classify_pe_file('uploads/hello.exe')
