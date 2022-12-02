# aws-admin

This module was extracted out of AVL _admin module to be more generic and to be used
in Jupyterhub process when spawning a new user environment. It creates (if not already present) an
IAM user with permissions to read and write to the project-specfic user's prefix in
the user bucket, and creates and returns access credentials for this IAM
user, which the Jupyter Hub process can then pass to the user environment
in environment variables.

## Instal admin module
```
$ conda create --name aws-admin 
$ conda activate aws-admin
$ conda install -n aws-admin boto3 pytest moto
$ python setup.py develop
```