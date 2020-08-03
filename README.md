# phoebus
auto-add your IP address to an AWS security group


Description reference: https://github.com/piyushsonigra/aws_ipadd/blob/master/aws_ipadd

```
def allow_ip_permission(security_group_id, ip):
    session.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {
                'FromPort': port,
                'ToPort': port,
                'IpProtocol': 'tcp',
                'IpRanges': [{'CidrIp': ip, 'Description': rule_name}]
            }])
 ```


nice reference: 

https://serverfault.com/questions/675679/automatically-add-current-public-ip-to-security-group-to-allow-traffic-on-specif


keytool -import -trustcacerts -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit -alias Root -import -file /tmp/apigee.cert

docker exec -ti mfa-deploy_mfa-core-service_1 keytool -import -trustcacerts -keystore $JAVA_HOME/jre/lib/security/cacerts -storepass changeit -alias Root -import -file /tmp/apigee.cert
