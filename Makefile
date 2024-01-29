# This is a makefile for building and managing savd project.

default: help

# Target: all
# Description: Build the entire project.
all:
	@echo "Building the project..."

# Target: clean
# Description: Clean the project by removing all generated files.
clean:
	@echo "Cleaning the project..."

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
	wget https://mirrors.bfsu.edu.cn/anaconda/miniconda/Miniconda3-py39_23.11.0-2-Linux-x86_64.sh
	chmod +x Miniconda3-py39_23.11.0-2-Linux-x86_64.sh
	./Miniconda3-py39_23.11.0-2-Linux-x86_64.sh -b -p $(HOME)/miniconda3
	echo 'export PATH="$(HOME)/miniconda3/bin:$$PATH"' >> $(HOME)/.bashrc
	source $(HOME)/.bashrc
	conda create -n savd python=3.9
	conda activate savd