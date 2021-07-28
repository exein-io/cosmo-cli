#!/usr/bin/env bash

INSTALLER_NAME=exein-analyzer-cli-installer.run
BASEDIR=$(dirname "$0")
PACKAGING_DIR=$BASEDIR/release_include_files

# Set current directory to the repository root
cd $BASEDIR

# Statically build the executable in release mode
cargo build --target x86_64-unknown-linux-musl --release 
# Strip the executable
strip target/x86_64-unknown-linux-musl/release/efa

# Prepare package source folder
TMP_DIR=$(mktemp -d)
cp -r $PACKAGING_DIR/* $TMP_DIR
cp target/x86_64-unknown-linux-musl/release/efa $TMP_DIR

# Create the self-extractable archive
TMP_INSTALLER_FILE=/tmp/$INSTALLER_NAME
makeself $TMP_DIR $TMP_INSTALLER_FILE "exein-cli" ./setup.sh

# Move the result to target folder
cp $TMP_INSTALLER_FILE target/$INSTALLER_NAME
echo ""
echo "Packaged file: target/$INSTALLER_NAME"

# Clean temporary files
rm $TMP_INSTALLER_FILE
rm -rf $TMP_DIR