# Report for PAC: Personalized Anonymous Communication

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
   - Launch an EC2 instance.
   - Run `aws configure` on your EC2 to set up AWS credentials.

2. **Install Go:**
   - Make sure the Go programming language is installed on your EC2 instance.

3. **Clone the Repository:**
   - Clone this repository onto your EC2 machine.

4. **Navigate to the CTCollector folder:**
   ```bash
   cd CTCollector
   ```

5. **Start the Protocol:**
   - Run the following command:
     ```bash
     go run main.go
     ```

This will start the `CTCollector`, launch the protocol with a preset number of clients, and generate a `report.json` file in the same folder.
