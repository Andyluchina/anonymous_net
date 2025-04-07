# report for PAC: Personalized Anonymous Communication
The CTAuditor folder is for the auditor code

The CTClient folder is for the client code

The CTCollector folder is for the information and stats collection throughout the protocol process, spawning the client, auditor and collect run time info

The CTPinger is simply a pinging server that periodically checks if the collector is alive

This is a system that runs on aws, to get start, you need to have an aws account.

you will first need to get a aws ec2 machine and run aws configure to set up appropriate aws credentials.You also need to make sure go is installed.

Clone the whole code base and move to the CTCollector folder.

simply run

go run main.go 

to start up the CTCollector and it will run the protocol with preset numbers of clients and generate report.json in the folder



