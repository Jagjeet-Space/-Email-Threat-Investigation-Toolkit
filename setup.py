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

)
