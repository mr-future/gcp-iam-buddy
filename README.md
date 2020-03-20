# gcp-iam-buddy
## Overview
This missing link in GCP IAM management allows you to view the comprehensive permissions of each member. It also can recursively delete a member from the organization.

## Requirements:
* Python3
* Libraries in requirements.txt
* Google Cloud SDK

## Setup
```
# install requirements
pip3 install -r requirements.txt

# edit iam-buddy.py, specify value for org_id and org_name
```

## Usage
```
# download and process IAM permissions (this can take several minutes)
./iam-buddy.py -g
# now search members.yaml file to see comprehensive permissions of individual members

# delete a member from IAM
./iam-buddy.py -d user@email.com

# for faster development, you can run processing independently of downloading IAM
./iam-buddy.py -x
```