# Code repo for PAC: Personalized Anonymous Communication

## Folder Structure

- **CTAuditor**  
  Contains the auditor code.

- **CTClient**  
  Contains the client code.

- **CTCollector**  
  Handles information and statistics collection throughout the protocol process.  
  It also spawns the client, auditor, and collects runtime info.

- **CTPinger**  
  A lightweight pinging server that periodically checks if the collector is alive.

## Getting Started

This system is designed to run on AWS. To begin:

1. **Set up AWS:**
   - Ensure you have an AWS account.
   - Launch an EC2 instance, be sure to Allow HTTPS traffic from the internet and  Allow HTTP traffic from the internet, and use Amazon Linux 2023 AMI 2023.7.20250331.0 x86_64 HVM kernel-6.1. 
   - Run `aws configure` on your EC2 to set up AWS credentials.

2. **Install Go:**
   - Make sure the Go programming language is installed on your EC2 instance.

3. **Clone the Repository:**
   - Clone this repository onto your EC2 machine(note that the current link is for viewing only, and use the following command to clone from a anonymous organization):
   ```bash
   sudo yum install -y git
   git clone https://github.com/ccs2025anonymous/anonymous_net
   ```

4. **Navigate to the CTCollector folder:**
   ```bash
   cd anonymous_net
   cd CTCollector
   ```

5. **Start the Protocol:**
   - Run the following command:
     ```bash
     sudo su
     go run main.go
     ```

This will start the `CTCollector`, launch the protocol with 30 clients(with 3 clients sitting out), and generate a `report.json` file in the same folder.

This is for demonstration only, to run with a large number of clients, I would suggest changing the main.go of the CTCollector line 23:
total_clients := []uint32{30}
to
total_clients := []uint32{100, 80, 60, 40, 20}
Where the system will sequentially run the protocol of these numbers of clients

## locally run
TO run the protocol locally, check out the FTChainingZKNonInteractive folder and see the readme there. The protocol will run with some logging without any networking or RPCs