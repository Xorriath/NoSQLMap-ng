import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
except OSError:
    # README is only metadata; never let a missing file break the install.
    long_description = ""

setup(
    name="NoSQLMap-ng",
    version="0.8",
    packages=find_packages(),

    entry_points={
        "console_scripts": [
            "nosqlmap-ng = nosqlmap.cli:cli"
        ]
    },

    python_requires=">=3.6",
    install_requires=[
        "CouchDB>=1.2,<2",
        "httplib2>=0.20",
        "pymongo>=4.0,<5",
        "requests>=2.28,<3",
    ],

    author="tcstool",
    author_email="codingo@protonmail.com",
    description="Automated MongoDB and NoSQL web application exploitation tool",
    license="GPLv3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://www.nosqlmap.net",
)
