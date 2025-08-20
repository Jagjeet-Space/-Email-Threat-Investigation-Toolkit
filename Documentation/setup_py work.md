setup.py is the one who helps in installing Phishscan CLI tool it is important to know how things works in setup.py that it lead to installation of Phishscan.

For installation of Phishscan user have to write these cmd.
``` bash
pip install .
phishscan -f sample.eml
```
**Note:** When you run `pip install .` make sure your in same directory as setup.py scipt in.




We will analyze setup.py in two phases: first, the metadata and basic info; second, the dependencies, CLI setup, and compatibility.

Lets analyze and understand 1st Phase of setup.py and know what every fuction do in it.

## Phase 1

```python

  from setuptools import setup, find_packages

setup(
    name='phishscan',
    version='0.1.0',  # First version, let's start with 0.1.0
    description='A professional CLI tool to analyze email headers and body for phishing indicators.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Jagjeet',
    author_email='jagjeetspace@gmail.com',
    url='https://github.com/Jagjeet-Space/-Email-Threat-Investigation-Toolkit/tree/Phishscan/Phishscan',  # Replace with your GitHub URL
```

1st line of our scripts uses *`from setuptools import setup, find_packages`*

- **Purpose:** Imports setup() and find_packages() from setuptools.
- *setup()* is the main function that tells Python how to install your package.
- *find_packages()* automatically discovers all Python packages our your project directory.


```python
setup(
    name='phishscan'
```
- name: The package name that will be used during installation (pip install phishscan)

```python
  version='0.1.0',  # First version, let's start with 0.1.0
  description='A professional CLI tool to analyze email headers and body for phishing indicators.',
```
- version: Current version of our tool
- format: MAJOR.MINOR.PATCH
- description: Short, human-readable explanation of the package.
- Appears in pip listings or when searching packages.

```python
        long_description=open('README.md').read(),
        long_description_content_type='text/markdown',
```
- *long_description:* Reads the full README.md as a detailed description of the package
- *long_description_content_type:* Tells setuptools that the README is in Markdown format.
- This ensures your docs look correct on PyPI listing.
- **Note:** Remember if README.md doesn’t exist, this will fail. Always ensure the file is in the same directory as setup.py.

```python
    author='Jagjeet',
    author_email='jagjeetspace@gmail.com',
    url='https://github.com/Jagjeet-Space/-Email-Threat-Investigation-Toolkit/tree/Phishscan/Phishscan',
```
- url: User can click to see source code, issues, or contribute.


## Phase 2  

```python
    packages=find_packages(),
    install_requires=[
        'pyfiglet',
        'termcolor',
        'dnspython',
    ],
    entry_points={
        'console_scripts': [
            'phishscan = phishscan.phishscan:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Topic :: Security',
    ],
    python_requires='>=3.6',
```

1st line from 2nd Phase 

```python
       packages=find_packages(),
```
- Uses *find_packages()* to automatically find all Python packages in the project.
- __init__.py helps *find_packages()* function to automatically find packages in direcotry.

```python
       install_requires=[
        'pyfiglet',
        'termcolor',
        'dnspython',
    ],
```
- *install_requires*: List of dependecies that pip will install automatically.
- When users run ```bash pip install phishscan```, these dependencies will automatically be installed

```python
         entry_points={
        'console_scripts': [
            'phishscan = phishscan.phishscan:main',
        ],
    },

```
- *entry_points:* Defines CLI commands for our tool.
  -  *entry_points* is a special setuptools parameter that tells Python to create executable commands when the package is installed.
  -  It’s what allows your Python script to be run directly from the terminal like any other command, without needing to type python phishscan/phishscan.py.
- `phishscan = phishscan.phishscan:main` This is slpit in two parts mean:
  1. 1st phishscan mean- This is the command users will type in the terminal after installation.
  2. 2nd phishscan aftet dot means- Pyhton module path: the phishscan.py file inside the phishscan package.
    - :main- The function to call when this command is executed.
    - Executes the main() function inside phishscan/phishscan.py.
 
- This is what turns our Python package into a real command-line tool that behaves like any other Linux or Windows executable.
 
```python
           classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Environment :: Console',
        'Topic :: Security',
    ],
```
- *classifiers:* Metadata about our package. Helps people and tool search for it.

```python
          python_requires='>=3.6',
)
```
- python_requires: Minimum Python version required to run the package.
```scss
  setup.py
   ├─ Metadata (Phase 1)
   ├─ Dependencies (Phase 2)
   ├─ CLI creation (entry_points)
   └─ Installation flow via pip
```

So this is the end of our setup.py explanation.

