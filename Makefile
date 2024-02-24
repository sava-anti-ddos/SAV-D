# This is a makefile for building and managing savd project.

# Variables
SHELL		= /bin/bash
HOME 		= $(shell echo $$HOME)

default: help

# Target: all
# Description: Build the entire project.
all:
	@echo "Building the project..."

# Target: clean
# Description: Clean the project by removing all generated files.
clean:
	@echo "Cleaning the project..."
# remove _pycache_ files
	@find . -name "__pycache__" -type d -exec rm -rf {} \;
	@rm -rf /tmp/upload*
	@rm -rf /tmp/sniffer*
	@rm -rf blacklist.db

# Target: run
# Description: Run the project.
run:
	@echo "Running the project..."

# Target: install
# Description: Install the project.
install:
	@echo "Installing the project..."


help:
	@echo "make deps		install dependencies"
	@echo "make help		display this help message"
	@echo "make install		install the project"
	@echo "make run		run the project"
	@echo "make test		run the tests"
	@echo "make clean		clean the project"

deps:
	@echo "Installing dependencies..."
	@echo "Needs root privileges to install dependencies"
	
# install python3
	@echo -e "\033[32mInstalling python3 enviornment\033[0m"
	sudo apt install python3 python-is-python3 python3-pip -y

# install mininet
	@echo -e "\033[32mInstalling mininet enviornment\033[0m"
	sudo apt install mininet -y

# install quagga
	@echo -e "\033[32mInstalling quagga enviornment\033[0m"
	sudo apt install quagga -y

# install xterm
	@echo -e "\033[32mInstalling xterm enviornment\033[0m"
	sudo apt install xterm -y

clean_deps:
	@echo "Cleaning dependencies..."
	@echo "Needs root privileges to clean dependencies"
	
# remove python3
	@echo -e "\033[32mRemoving python3 enviornment\033[0m"
	sudo apt remove python3 python-is-python3 python3-pip -y

# remove mininet
	@echo -e "\033[32mRemoving mininet enviornment\033[0m"
	sudo apt remove mininet -y

# remove quagga
	@echo -e "\033[32mRemoving quagga enviornment\033[0m"
	sudo apt remove quagga -y

# remove xterm
	@echo -e "\033[32mRemoving xterm enviornment\033[0m"
	sudo apt remove xterm -y