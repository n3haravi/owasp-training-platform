#!/bin/bash

# Folder to store JSON reports
REPORT_DIR="$HOME/owasp-project/json-reports"
mkdir -p "$REPORT_DIR"

# -------------------------------
# Juice Shop
# -------------------------------
JUICE_TOKEN="sqp_04da988802d776230c7c4653a2f37d8181604fac"
JUICE_PROJECT="OWASP-juice-shop"

echo "Downloading Juice Shop issues..."
curl -s -u "$JUICE_TOKEN": \
"http://localhost:9000/api/issues/search?componentKeys=$JUICE_PROJECT&p=1&ps=500" \
-o "$REPORT_DIR/juice-shop-issues.json"

echo "Downloading Juice Shop hotspots..."
curl -s -u "$JUICE_TOKEN": \
"http://localhost:9000/api/hotspots/search?projectKey=$JUICE_PROJECT&p=1&ps=500" \
-o "$REPORT_DIR/juice-shop-hotspots.json"

# -------------------------------
# WebGoat
# -------------------------------
WEBGOAT_TOKEN="sqp_6f07d86188c29f767ffb9d2f8d6e0905d2ed1efc"
WEBGOAT_PROJECT="webgoat"

echo "Downloading WebGoat issues..."
curl -s -u "$WEBGOAT_TOKEN": \
"http://localhost:9000/api/issues/search?componentKeys=$WEBGOAT_PROJECT&p=1&ps=500" \
-o "$REPORT_DIR/webgoat-issues.json"

echo "Downloading WebGoat hotspots..."
curl -s -u "$WEBGOAT_TOKEN": \
"http://localhost:9000/api/hotspots/search?projectKey=$WEBGOAT_PROJECT&p=1&ps=500" \
-o "$REPORT_DIR/webgoat-hotspots.json"

echo "✅ All JSON reports downloaded to $REPORT_DIR"
ls -lh "$REPORT_DIR"
