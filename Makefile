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
# remove miniconda3 tmp files
	@rm -rf Miniconda3-py39_23.11.0-2-Linux-x86_64.sh
# remove _pycache_ files
	@find . -name "__pycache__" -type d -exec rm -rf {} \;

# Target: run
# Description: Run the project.
run:
	@echo "Running the project..."

help:
	@echo "make deps		install dependencies"
	@echo "make help		display this help message"
	@echo "make install		install the project"
	@echo "make run		run the project"
	@echo "make test		run the tests"
	@echo "make clean		clean the project"

deps:
	@echo "Installing dependencies..."
	
	# install miniconda3
	@echo -e "\033[32mInstalling miniconda3...\033[0m"
	wget https://mirrors.bfsu.edu.cn/anaconda/miniconda/Miniconda3-py39_23.11.0-2-Linux-x86_64.sh
	chmod +x Miniconda3-py39_23.11.0-2-Linux-x86_64.sh
	./Miniconda3-py39_23.11.0-2-Linux-x86_64.sh -u -b -p $(HOME)/miniconda3

	@echo -e "\033[32mConfiguring miniconda3...\033[0m"
	echo 'export PATH="$(HOME)/miniconda3/bin:$$PATH"' >> $(HOME)/.bashrc
	$(SHELL) -c "source $(HOME)/.bashrc"
	@echo -e "\033[32mInstalling python3.9...\033[0m"
	conda create -n savd python=3.9 -y
	conda init
	@echo -e "\033[32mRun 'conda activate savd' to ensure python3 env installed...\033[0m"