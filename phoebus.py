import boto3, sys
from botocore.exceptions import ClientError


import requests
# http://jpiedra.github.io/article/never-update-security-group/
AMAZON_IP_ENDPOINT = 'http://checkip.amazonaws.com/'


region = 'us-east-2'	#Virginia
ec2 = boto3.client('ec2',region);
#print ("I seme to be working");
region = 'us-east-2'
#ec2 = boto3.resource('ec2',region);

groupID='sg-0a61a4df2fa28d659'

#this is for using your device ... not to use as a web-app
def get_current_ip():
    resp = requests.get(AMAZON_IP_ENDPOINT)
    resp.raise_for_status()
    print resp.content.strip() + '/32'

def xz_loadAWSSecuriyGroup():
    try:
        security_group = ec2.SecurityGroup(groupID);
        print len(security_group.ip_permissions);
        print (security_group.ip_permissions)

    except ClientError as e:
        print(e)

def loadAWSSecuriyGroup():
    try:
        response = ec2.describe_security_groups(GroupIds=[groupID]);
#        ipcidr = response['SecurityGroups'][0]['IpPermissions'][0]['IpRanges'][0]['CidrIp']
#        print ('Removing IP block %s' % (ipcidr));

        old_access = response['SecurityGroups'][0]['IpPermissions'][0]
        print(old_access)

#        removeOldSecurityGroup(old_access)
    
#need to capture 'IndexError' when nothing is in the sucurity group
    except ClientError as e:
        print(e)

def removeOldSecurityGroup(old_access):
    
    try:
        data = ec2.revoke_security_group_ingress(
        GroupId=groupID,
        IpPermissions=[	
            old_access
        ])
        print("DELETE REPONSE %s" % (data));  
    
#need to capture 'IndexError' when nothing is in the sucurity group
    except ClientError as e:
        print(e)

def addIPAddress():
    ext_ip = '11.11.11.1/32'
    try:
	    data = ec2.authorize_security_group_ingress(
        GroupId=groupID,
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 3389,
                'ToPort': 3389,
                'IpRanges': [{'CidrIp': ext_ip}]
            }    
        ])
	    print("addIPAddress Response: %s" % (data));  
    except ClientError as e:
        print(e)

def check_arguments(args):
    print('not used as this time')


def get_last_ip():
    try:
        with open(LAST_IP_FILENAME, 'r') as fp:
            ip = fp.readline().strip()
    except:
        ip = None
    return ip

def delete_ip(sg, ip):
    if not sg.revoke('tcp', FROM_PORT, TO_PORT, cidr_ip=ip):
        raise Exception('Removing ip from security group failed')

def add_new_ip(ip):
    if not sg.authorize('tcp', FROM_PORT, TO_PORT, cidr_ip=ip):
        raise Exception('Adding ip to security group failed')

def save_new_ip(ip):
    with open(LAST_IP_FILENAME, 'w') as fp:
        fp.write(ip + '\n')


def final_main_function_when_completed():
    last_ip = get_last_ip()
    current_ip = get_current_ip()

    if last_ip == current_ip:
        print 'Last ip and current ip are the same.. abort.'
        exit(0)

    conn = get_connection()
    sg = get_security_group(conn, GROUP_NAME)
    if last_ip is not None:
        print 'Found old ip {}'.format(last_ip)
        delete_ip(sg, last_ip)
        print '    ..deleted successfully..'
    else:
        print 'No old ip was found..'

    print 'Current ip is {}'.format(current_ip)
    add_new_ip(current_ip)
    print '    ..updated successfully'
    save_new_ip(current_ip)



def main(args):
	print('main....')
	get_current_ip()
#	addIPAddress()
#    loader = ContainerLoader()
#    loader.main(sys.argv[1:])

if __name__ == '__main__':
    main(sys.argv[1:])