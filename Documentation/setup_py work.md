setup.py is the one who helps in installing Phishscan CLI tool its important to know how things works in setup.py that it lead to installation of Phishscan.

Lets analyze and understand python code of setup.py what every fuction do in it

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

```python
    author='Jagjeet',
    author_email='jagjeetspace@gmail.com',
    url='https://github.com/Jagjeet-Space/-Email-Threat-Investigation-Toolkit/tree/Phishscan/Phishscan',
```
- url: User can click to see source code, issues, or contribute.
