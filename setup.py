from setuptools import find_packages, setup


with open("README.md") as f:
	setup(
			name = "NoSQLMap-ng",
			version = "0.8",
			packages = find_packages(),

			entry_points = {
				"console_scripts": [
					"nosqlmap-ng = nosqlmap.cli:cli"
					]
				},

			python_requires = '>=3.6',
			install_requires = ["CouchDB>=1.2", "httplib2>=0.20",
								 "pymongo>=4.0", "requests>=2.28"],

			author = "tcstool",
			author_email = "codingo@protonmail.com",
			description = "Automated MongoDB and NoSQL web application exploitation tool",
			license = "GPLv3",
			long_description = f.read(),
			url = "http://www.nosqlmap.net"
		)
