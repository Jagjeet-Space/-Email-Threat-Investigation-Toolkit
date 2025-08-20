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

