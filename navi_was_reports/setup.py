from setuptools import setup, find_packages
from os import path


this_directory = path.abspath(path.dirname(__file__))

with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='navi.was',
    version='0.0.1',
    description="A Flask based Reporting engine for Tenable WAS",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Casey Reid",
    author_email="itprofguru@gmail.com",
    url="https://github.com/packetchaos/Navi",
    license="GNUv3",
    keywords='tenable tenable_io navi tio, lumin, navi pro, tio cli, tenable io cli',
    packages=find_packages(exclude=['docs', 'tests']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'requests',
        'flask',
        'dateutil'
    ],
    python_requires='>=3.0'
)
