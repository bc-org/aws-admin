from setuptools import setup, find_packages
packages = find_packages(exclude=["test", "test.*"])
version = None
with open('aws_admin/version.py') as f:
    exec(f.read())
setup(
    name="aws_admin",
    version=version,
    packages=packages
)
