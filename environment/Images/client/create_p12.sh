#!/bin/bash

# Ask user for the ZIP file name
read -p "Enter the name of the ZIP file (e.g., certs.zip): " ZIPFILE

# Check if ZIP exists
if [ ! -f "$ZIPFILE" ]; then
    echo "Error: File '$ZIPFILE' not found."
    exit 1
fi

# Create a temporary working directory
TMPDIR=$(mktemp -d)
echo "Using temporary directory: $TMPDIR"

# Unzip into the temp directory only
echo "Unzipping '$ZIPFILE' into $TMPDIR ..."
unzip -o "$ZIPFILE" -d "$TMPDIR"

if [ $? -ne 0 ]; then
    echo "Failed to unzip '$ZIPFILE'."
    rm -rf "$TMPDIR"
    exit 1
fi

echo "Unzip completed."

# Find all .crt.pem files inside temp directory
cert_files=$(find "$TMPDIR" -maxdepth 1 -type f -name "*.crt.pem")

if [ -z "$cert_files" ]; then
    echo "No .crt.pem files found inside the ZIP."
    rm -rf "$TMPDIR"
    exit 0
fi

# Process each certificate file
for crt_file in $cert_files; do
    base_name=$(basename "$crt_file" .crt.pem)
    key_file="$TMPDIR/${base_name}.key.pem"
    p12_file="${base_name}.p12"   # output in current directory

    echo "Found certificate: $crt_file"

    if [ -f "$key_file" ]; then
        echo "Matching key found: $key_file"
        echo "Creating PKCS#12 file: $p12_file"

        openssl pkcs12 -export \
            -in "$crt_file" \
            -inkey "$key_file" \
            -out "$p12_file" \
            -name "$base_name"

        if [ $? -eq 0 ]; then
            echo "Successfully created $p12_file"
        else
            echo "Failed to create $p12_file" >&2
        fi
    else
        echo "No matching key for $crt_file (expected $key_file). Skipping."
    fi
done

# Clean up temporary directory
echo "Cleaning up temporary directory..."
rm -rf "$TMPDIR"

echo "Done."
