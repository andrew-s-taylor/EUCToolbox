#!/bin/bash

# Parameters
WEBHOOK_COMMUNITY=$1
WEBHOOK_MANIFEST=$2
APP_ID=$3
APP_SECRET=$4
SENDGRID_TOKEN=$5
GIT_REPO_URL=$6
SUBDIRECTORY_PATH=$7

# Clone the repository
git clone $GIT_REPO_URL repo

# Copy the contents of the specified subdirectory to the web root
cp -r repo/$SUBDIRECTORY_PATH/* /home/site/wwwroot/

# Clean up
rm -rf repo

# Restart the web server to apply the changes
service apache2 restart

# Path to the config.php file in the subdirectory
CONFIG_FILE="/home/site/wwwroot/config.php"

# Update the config.php file with the provided parameters
sed -i "s/COMMUNITYWEBHOOKHERE/$WEBHOOK_COMMUNITY/g" $CONFIG_FILE
sed -i "s/MANIFESTWEBHOOKHERE/$WEBHOOK_MANIFEST/g" $CONFIG_FILE
sed -i "s/APPID/$APP_ID/g" $CONFIG_FILE
sed -i "s/APPSECRET/$APP_SECRET/g" $CONFIG_FILE
sed -i "s/SENDGRIDTOKEN/$SENDGRID_TOKEN/g" $CONFIG_FILE

# Restart the web server to apply the changes
service apache2 restart