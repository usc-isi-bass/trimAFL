from setuptools import setup, find_packages

try:
    packages = find_packages()
except ImportError:
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='trimAFL',
    version='0.0.1',
    author='Wei-Cheng Wu',
    author_email='wwu@isi.edu',
    packages=packages,
    include_package_data=True,
    install_requires=[
        'argparse', 
        'angr', 
        'bingraphvis', 
        'flask', 
        'cfg-explorer',
        'r2pipe'],
    description='trimAFL',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/usc-isi-bass/trimAFL',
)
