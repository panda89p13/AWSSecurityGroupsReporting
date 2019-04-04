#!/usr/local/bin/python3
import csv
import boto3
from argparse import ArgumentParser

def listrules(rulelist):
	rules = []
	for rule in rulelist:
		if rule['IpProtocol'] == "-1":
			ip_protocol = "All"
			to_port = "All"
		else:
			ip_protocol = rule['IpProtocol']
			to_port = rule['ToPort']
			# If ICMP, report "N/A" for port #
			if to_port == -1:
				to_port = "N/A"

		# Is source/target an IP v4?
		if len(rule['IpRanges']) > 0:
			for ip_range in rule['IpRanges']:
				rules.append({"Protocol": ip_protocol, "Port": to_port, "Source/Destination":ip_range['CidrIp']})

		# Is source/target an IP v6?
		if len(rule['Ipv6Ranges']) > 0:
			for ip_range in rule['Ipv6Ranges']:
				rules.append({"Protocol": ip_protocol, "Port": to_port, "Source/Destination": ip_range['CidrIpv6']})

		# Is source/target a security group?
		if len(rule['UserIdGroupPairs']) > 0:
			for source in rule['UserIdGroupPairs']:
				rules.append({"Protocol": ip_protocol, "Port": to_port, "Source/Destination": source['GroupId']})
	return rules



def main():
	parser = ArgumentParser(description='Security Groups Rules Report in each Region type -h for help')
	parser.add_argument('-r', '--region',nargs ='*' ,dest='regions',required=True,help="Region name ex:'us-east-1")
	options = parser.parse_args()
	if (options.regions== None):
		print ( "Please enter atleast one region ")
		exit(0)
	else:
		headers = ["Group-Name", "Group-ID", "InBound/OutBound", "Protocol", "Port", "Source/Destination"]
		Rows = []
		for region in options.regions :
			ec2=boto3.client('ec2', region )
			sgs = ec2.describe_security_groups()["SecurityGroups"]
			for sg in sgs:
				grouprows ={}
				grouprows["Group-Name"] = sg['GroupName']
				grouprows["Group-ID"] = sg['GroupId']
				Rows.append(grouprows)
				inbound = sg['IpPermissions']
				Rows.append({"InBound/OutBound":"inbound"})
				Rows = Rows+listrules(inbound)
				outbound = sg['IpPermissionsEgress']
				Rows.append({"InBound/OutBound": "outbound"})
				Rows = Rows + listrules(outbound)
				with open (region+'-SGreports.csv','w') as report:
					report_csv = csv.DictWriter(report,headers)
					report_csv.writeheader()
					report_csv.writerows(Rows)
					report.close()

if  __name__ =='__main__':
	main()
