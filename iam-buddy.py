#! /usr/bin/env python3

import argparse, csv, json, os, subprocess, sys, yaml

# config variables
org_id=
org_name=
resources_file = 'resources.yaml'
members_file = 'members.yaml'
user_members_file = 'user_members.yaml'
user_members_csv = 'user-members.csv'
external_members_file = 'external-members.yaml'
group_members_file = 'group-members.yaml'

# init variables
resources = []
matched_permissions = []
members = []
user_members = []
group_members = []
external_members = []

def get_json(command):
    '''wrapper for subprocess to return json'''
    raw_output = subprocess.check_output(command)
    return json.loads(raw_output.decode("utf-8"))

def normalize_folder(folder, iam):
    '''convert gcloud folder json to common format for org, projects, and folders'''
    normalized = {}
    normalized['iam'] = iam
    normalized['name'] = folder['displayName']
    normalized['id'] = folder['name'].rsplit('/', 1)[-1]
    normalized['parent'] = folder['parent'].rsplit('/', 1)[-1]
    normalized['type'] = 'folder'
    return normalized

def recurse_folders(name):
    '''this function calls itself to recurse through all nested folders,
    getting iam and appending a dict object for each folder'''
    folder_id = name.rsplit('/', 1)[-1]
    folders = get_json(['gcloud', 'resource-manager', 'folders', 'list', 
        '--folder={}'.format(folder_id), '--format=json'])
    if folders:
        for folder in folders:
            iam = get_json(['gcloud', 'resource-manager', 'folders', 'get-iam-policy',
                '{}'.format(folder['name'].rsplit('/', 1)[-1]), '--format=json'])
            normalized = normalize_folder(folder, iam)
            resources.append(normalized)
            recurse_folders(folder['name'])
    return

def load_file(resources_file, script_name):
    '''load contents of iam file'''
    print('Loading iam policies from {}...'.format(resources_file))
    with open(resources_file, 'r') as stream:
        try:
            resources = yaml.load(stream, Loader=yaml.FullLoader)
        except FileNotFoundError:
            print('{0} not found.'
            '\ncreate it by running:' 
            '\n{1} -g '.format(resources_file, script_name))
    return resources

### argparse argument handling ###
parser = argparse.ArgumentParser()
script_name = parser.prog
# mutually exclusive groups prevent certain arguments from being used together
group0 = parser.add_mutually_exclusive_group()
group1 = parser.add_mutually_exclusive_group()
group2 = parser.add_mutually_exclusive_group()
group0.add_argument('-g','--get-iam',
    help='Retrieve iam policies on organization and all nested projects/folders.'
        ' Store policies as yaml in {}'.format(resources_file), action='store_true')
group1.add_argument('-d','--delete-member',
    help='Search file for email, then delete from org/folders/projects in GCP',
        nargs=1, action='store',metavar='<email>')
group2.add_argument('-x','--dev-mode',
    help='Since {} can take forever to download, skip download and process existing file'.format(resources_file),
        action='store_true')
args = parser.parse_args()

if args.get_iam:
    # get organization iam policy
    print('Loading organization IAM policy...')
    iam = projects = get_json(['gcloud', 'organizations', 'get-iam-policy', '{}'.format(org_id), '--format=json'])
    
    # convert gcloud json to common format for orgs, folders, and projects
    normalized = {}
    normalized['iam'] = iam
    normalized['name'] = org_name
    normalized['id'] = str(org_id)
    normalized['parent'] = 'NONE'
    normalized['type'] = 'organization'
    resources.append(normalized)

    # get all project info and iam polices
    print('Loading project IAM polices...')
    projects = get_json(['gcloud', 'projects', 'list', '--format=json'])
    for project in projects:
        iam = get_json(['gcloud', 'projects', 'get-iam-policy', '{}'.format(project['projectId']), '--format=json'])
        # convert gcloud json to common format for orgs, folders, and projects
        normalized = {}
        normalized['iam'] = iam
        normalized['name'] = project['name']
        normalized['id'] = project['projectId']
        try:
            normalized['parent'] = project['parent']['id']
        except KeyError:
            normalized['parent'] = 'NONE'
        normalized['type'] = 'project'
        resources.append(normalized)

    # get top-level folder info
    print('Loading folder IAM polices...')
    folders = get_json(['gcloud', 'resource-manager', 'folders', 'list',
        '--organization={}'.format(org_id), '--format=json'])

    # recurse  each top-level folder, getting folder info and iam policies
    for folder in folders:
        iam = get_json(['gcloud', 'resource-manager', 'folders', 'get-iam-policy',
            '{}'.format(folder['name'].rsplit('/', 1)[-1]), '--format=json'])
        normalized = normalize_folder(folder, iam)
        resources.append(normalized)
        recurse_folders(folder['name'])

    # write data to file
    print('Writing data to {}...'.format(resources_file))
    with open(resources_file, 'w+') as stream:
        yaml.dump(resources, stream)

if args.dev_mode or args.get_iam:
    resources = load_file(resources_file, script_name)
    for resource in resources:
        # filter out resources without iam bindings
        if 'bindings' in resource['iam']:
            # populate members list with dictionaries
            for binding in resource['iam']['bindings']:
                for member in binding['members']:
                    # check members list of dictionaries for member in email value
                    if not any(x['email'] == member.rsplit(':', 1)[-1] for x in members):
                        members.append(dict({
                            'email': member.rsplit(':', 1)[-1],
                            'type': member.rsplit(':', 1)[0],
                            'permissions': []
                        }))
                    for m in members:
                        if member.rsplit(':', 1)[-1] == m['email']:
                            if not any(f.get('resourceName', None) == resource['name'] for f in m['permissions']):
                                m['permissions'].append(dict({
                                    'resourceName': resource['name'],
                                    'resourceID': resource['id'],
                                    'resourceType': resource['type']
                                }))
                            perm_index = 0
            # iterate through members list of dictionaries adding roles list to resources
            for binding in resource['iam']['bindings']:
                for member in binding['members']:
                    for m in members:
                        if member.rsplit(':', 1)[-1] == m['email']:
                            for permission in m['permissions']:
                                if permission['resourceName'] == resource['name']:
                                    if 'roles' not in permission:
                                        permission['roles'] = []
                                    permission['roles'].append(binding['role'].rsplit('/', 1)[-1])
    
    members = sorted(members, key=lambda k: k['email'])

    # find user members and external members and add them to their own lists
    user_count = 0
    ext_user_count = 0
    for member in members:
        if member['type'] == 'user':
            user_count += 1
            user_members.append(member)
            if '@kw.com' not in member['email']:
                ext_user_count += 1
                external_members.append(member)
        elif member['type'] == 'group':
            group_members.append(member)

    # output some reporting
    print('Total user count: {}'.format(str(user_count)))
    print('Total external user count: {}'.format(str(ext_user_count)))

    # write data to files
    print('Writing data to {}...'.format(members_file))
    with open(members_file, 'w+') as stream:
        yaml.dump(members, stream)

    print('Writing data to {}...'.format(user_members_file))
    with open(user_members_file, 'w+') as stream:
        yaml.dump(user_members, stream)

    print('Writing data to {}...'.format(user_members_csv))
    with open(user_members_csv, 'w+') as stream:
        writer = csv.writer(stream)
        writer.writerow(['Email', 'Member Type', 'ResourceName', 'Resource Type', 'Role'])
        for member in external_members:
            for resource in member['permissions']:
                for role in resource['roles']:
                    writer.writerow([member['email'], member['type'], resource['resourceName'], resource['resourceType'], role])

    print('Writing data to {}...'.format(external_members_file))
    with open(external_members_file, 'w+') as stream:
        yaml.dump(external_members, stream)
    
    print('Writing data to {}...'.format(group_members_file))
    with open(group_members_file, 'w+') as stream:
        yaml.dump(group_members, stream)

    sys.exit(0)

if args.delete_member:
    target_member = args.delete_member[0]
    members = load_file(members_file, script_name)

    # prototype for finding a member
    for member in members:
        if member['email'] == target_member:
            for permission in member['permissions']:
                matched_permissions.append(permission)
            full_member = member['type'] + ':' + target_member
            break

    # return list of resources where target_member was found
    if matched_permissions:
        print('\n{} found in the following resources:\n'.format(target_member))
        for permission in matched_permissions:
            print(permission['resourceName'] + " - " + permission['resourceID'])
        print('')
    else:
        print('\n{} not found.\n'.format(target_member))

    # prompt for input to continue
    print('Are you sure you would like to remove {0} from the {1} kw.com organization iam policy, '
    'as well as iam policies for all nested folders and projects?'.format(target_member, org_name))
    input("Press Enter to continue...")

    # remove member from iam policy binding
    for permission in matched_permissions:
        if permission['resourceType'] == 'organization':
            for role in permission['roles']:
                print('Deleting {0} from organization {1}'.format(role, org_name))
                subprocess.check_output(['gcloud', 'organizations', 'remove-iam-policy-binding',
                    str(permission['resourceID']), '--member={}'.format(full_member), '--role=roles/{}'.format(role)])
        elif permission['resourceType'] == 'folder':
            for role in permission['roles']:
                print('Deleting {0} from folder {1}'.format(role, permission['resourceName']))
                subprocess.check_output(['gcloud', 'resource-manager', 'folders', 'remove-iam-policy-binding',
                    str(permission['resourceID']), '--member={}'.format(full_member), '--role=roles/{}'.format(role)])
        elif permission['resourceType'] == 'project':
            for role in permission['roles']:
                print('Deleting {0} from project {1}'.format(role, permission['resourceName']))
                subprocess.check_output(['gcloud', 'projects', 'remove-iam-policy-binding',
                    str(permission['resourceID']), '--member={}'.format(full_member), '--role=roles/{}'.format(role)])

    print('\nDeletions complete. Note that YAML files were not updated.')