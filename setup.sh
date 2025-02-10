#!/bin/bash

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Make the main script executable
chmod +x httpz.py

echo "Setup complete! Activate the virtual environment with: source venv/bin/activate" 