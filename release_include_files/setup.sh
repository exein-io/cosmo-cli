#!/usr/bin/env bash

# Run script as superuser
[ "$UID" -eq 0 ] || exec sudo "$0" "$@"

EXEIN_INSTALL_DIR=/opt/exein
EXEIN_CLI_NAME=cosmo

# Remove previous version if present
rm -rf $EXEIN_INSTALL_DIR
rm -f /usr/bin/$EXEIN_CLI_NAME

# Copy content to install directory
mkdir -p $EXEIN_INSTALL_DIR
mv ./$EXEIN_CLI_NAME $EXEIN_INSTALL_DIR/$EXEIN_CLI_NAME

# Change owner and adjust permissions
chown -R root:root $EXEIN_INSTALL_DIR
chmod -R 755 $EXEIN_INSTALL_DIR

# Create symlink in /usr/bin directory
ln -s $EXEIN_INSTALL_DIR/$EXEIN_CLI_NAME /usr/bin/$EXEIN_CLI_NAME
