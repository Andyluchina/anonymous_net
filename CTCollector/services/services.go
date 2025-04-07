package services

import (
	"CTCollector/datastruct"
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Collector struct {
	RunStats         []datastruct.TestRun
	RunTasks         []datastruct.RunTask
	CurrentTask      int
	RunningInstances []string
	KeyName          string
	CollectorIP      string
	AuditorIP        string
	mu               sync.Mutex
}

func awsCLI(args ...string) (string, error) {
	cmd := exec.Command("aws", args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		fmt.Println("AWS CLI Error:", stderr.String())
		return "", fmt.Errorf("%s: %w", stderr.String(), err)
	}
	return out.String(), nil
}

type RunInstancesOutput struct {
	Instances []struct {
		InstanceId string `json:"InstanceId"`
	} `json:"Instances"`
}

func extractInstanceIDsFromJSON(jsonData string) ([]string, error) {
	var result RunInstancesOutput
	err := json.Unmarshal([]byte(jsonData), &result)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}
	var ids []string
	for _, inst := range result.Instances {
		ids = append(ids, inst.InstanceId)
	}
	return ids, nil
}

func SpawnClients(collector *Collector, client_count string, server_ip string, collector_ip string, reveal int) error {
	region := "us-east-1"
	instanceType := "t2.small"
	securityGroupID := "sg-03c26d167c72f8254"
	count := client_count

	// Get the latest Amazon Linux 2 AMI ID
	amiID, err := awsCLI("ec2", "describe-images", "--owners", "amazon",
		"--filters", "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2",
		"Name=state,Values=available",
		"--query", "Images | sort_by(@, &CreationDate) | [-1].ImageId",
		"--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting AMI ID:", err)
		return err
	}
	amiID = strings.TrimSpace(amiID)
	fmt.Println("Using AMI ID:", amiID)

	// Find the default subnet in the first available zone
	subnetID, err := awsCLI("ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true", "--query", "Subnets[0].SubnetId", "--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting subnet ID:", err)
		return err
	}

	subnetID = strings.TrimSpace(subnetID)
	fmt.Println("Using default subnet ID:", subnetID)

	client_script_user_data := fmt.Sprintf(`#!/bin/bash
	sudo su
	cd ~
	yum install git -y
	git clone https://github.com/Andyluchina/CTClient
	cd CTClient
	./main %s %s %s`, server_ip, strconv.Itoa(reveal), collector_ip)

	userDataEncoded := base64.StdEncoding.EncodeToString([]byte(client_script_user_data))
	// Start EC2 instances
	fmt.Println("Launching instances...")
	launchOutput, err := awsCLI("ec2", "run-instances", "--image-id", amiID, "--instance-type", instanceType, "--count", count, "--key-name", collector.KeyName, "--security-group-ids", securityGroupID, "--subnet-id", subnetID, "--user-data", userDataEncoded, "--region", region)
	if err != nil {
		fmt.Println("Error launching instances:", err)
		return err
	}
	fmt.Println("Client Instances launched.")

	// Extract instance IDs (assume jq is installed or use another method to parse JSON)
	instanceIDs, err := extractInstanceIDsFromJSON(launchOutput)
	if err != nil {
		fmt.Println("Error extracting instance IDs:", err)
		return err
	}

	collector.RunningInstances = append(collector.RunningInstances, instanceIDs...)
	return nil
}

func SpawnAuditor(collector *Collector) string {
	region := "us-east-1"
	instanceType := "t2.large"
	securityGroupID := "sg-03c26d167c72f8254"

	// Get the latest Amazon Linux 2 AMI ID using a custom function that wraps AWS CLI calls
	amiID, err := awsCLI("ec2", "describe-images", "--owners", "amazon",
		"--filters", "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2",
		"Name=state,Values=available",
		"--query", "Images | sort_by(@, &CreationDate) | [-1].ImageId",
		"--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting AMI ID:", err)
		panic(err)
	}
	amiID = strings.TrimSpace(amiID)

	// Find the default subnet in the first available zone
	subnetID, err := awsCLI("ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true",
		"--query", "Subnets[0].SubnetId", "--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting subnet ID:", err)
		panic(err)
	}
	subnetID = strings.TrimSpace(subnetID)

	// Prepare user data script for the instances
	userData := fmt.Sprintf(`#!/bin/bash
	sudo yum install -y git
	git clone https://github.com/Andyluchina/CTAuditor
	cd CTAuditor
	./main %s %s %s %s`, strconv.Itoa(int(collector.RunTasks[collector.CurrentTask].TotalClients)), strconv.Itoa(int(collector.RunTasks[collector.CurrentTask].MaxSitOut)), "80", collector.CollectorIP)
	userDataEncoded := base64.StdEncoding.EncodeToString([]byte(userData))

	// Start EC2 instances
	launchOutput, err := awsCLI("ec2", "run-instances", "--image-id", amiID, "--instance-type", instanceType, "--count", "1", "--key-name", collector.KeyName, "--security-group-ids", securityGroupID, "--subnet-id", subnetID, "--user-data", userDataEncoded, "--region", region)

	if err != nil {
		fmt.Println("Error launching instances:", err)
		panic(err)
	}
	instanceIDs, err := extractInstanceIDsFromJSON(launchOutput)
	if err != nil {
		fmt.Println("Error extracting instance IDs:", err)
		panic(err)
	}

	collector.RunningInstances = append(collector.RunningInstances, instanceIDs...)
	instanceID := instanceIDs[0]
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ip, err := getPublicIP(instanceID)
			if err != nil {
				fmt.Println("Error retrieving IP:", err)
				continue
			}
			if ip != "" {
				fmt.Println("Public IP found:", ip)
				collector.AuditorIP = ip + ":80"
				return ip + ":80"
			}
			fmt.Println("Public IP not available yet, retrying...")
		}
	}

}

func SpawnPinger(collector *Collector) error {
	region := "us-east-1"
	instanceType := "t2.medium"
	securityGroupID := "sg-03c26d167c72f8254"

	// Get the latest Amazon Linux 2 AMI ID using a custom function that wraps AWS CLI calls
	amiID, err := awsCLI("ec2", "describe-images", "--owners", "amazon",
		"--filters", "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2",
		"Name=state,Values=available",
		"--query", "Images | sort_by(@, &CreationDate) | [-1].ImageId",
		"--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting AMI ID:", err)
		panic(err)
	}
	amiID = strings.TrimSpace(amiID)

	// Find the default subnet in the first available zone
	subnetID, err := awsCLI("ec2", "describe-subnets", "--filters", "Name=default-for-az,Values=true",
		"--query", "Subnets[0].SubnetId", "--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error getting subnet ID:", err)
		panic(err)
	}
	subnetID = strings.TrimSpace(subnetID)

	// Prepare user data script for the instances
	userData := fmt.Sprintf(`#!/bin/bash
	sudo yum install -y git
	git clone https://github.com/Andyluchina/CTPinger
	cd CTPinger
	./main %s`, collector.AuditorIP)
	userDataEncoded := base64.StdEncoding.EncodeToString([]byte(userData))

	// Start EC2 instances
	launchOutput, err := awsCLI("ec2", "run-instances", "--image-id", amiID, "--instance-type", instanceType, "--count", "1", "--key-name", collector.KeyName, "--security-group-ids", securityGroupID, "--subnet-id", subnetID, "--user-data", userDataEncoded, "--region", region)

	if err != nil {
		fmt.Println("Error launching instances:", err)
		panic(err)
	}
	instanceIDs, err := extractInstanceIDsFromJSON(launchOutput)
	if err != nil {
		fmt.Println("Error extracting instance IDs:", err)
		panic(err)
	}

	collector.RunningInstances = append(collector.RunningInstances, instanceIDs...)
	return nil

}

func getPublicIP(instanceID string) (string, error) {
	cmd := exec.Command("aws", "ec2", "describe-instances", "--instance-ids", instanceID,
		"--query", "Reservations[*].Instances[*].NetworkInterfaces[*].Association.PublicIp",
		"--output", "text")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Read the output and return the first non-empty line
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("no public IP found")
}

func ExecuteCurrentTask(collector *Collector) error {

	collector.RunStats = append(collector.RunStats, datastruct.TestRun{
		Clients: []datastruct.ClientStats{},
		Auditor: datastruct.AuditorReport{},
	})

	collector.RunningInstances = []string{}

	fmt.Print("Executing a new task ")
	fmt.Println(collector.RunTasks[collector.CurrentTask])
	auditor_ip := SpawnAuditor(collector)

	// Spawn Pinger
	err := SpawnPinger(collector)

	if err != nil {
		panic(err)
	}
	time.Sleep(20 * time.Second)
	total_clients := collector.RunTasks[collector.CurrentTask].TotalClients
	sitout := collector.RunTasks[collector.CurrentTask].MaxSitOut
	err = SpawnClients(collector, strconv.Itoa(int(total_clients-sitout)), auditor_ip, collector.CollectorIP, 1)
	if err != nil {
		panic(err)
	}

	err = SpawnClients(collector, strconv.Itoa(int(sitout)), auditor_ip, collector.CollectorIP, 0)
	if err != nil {
		panic(err)
	}

	return nil
}

func Cleanup(collector *Collector) error {
	// Terminate instances
	fmt.Println("Terminating instances...")
	// Assuming instanceIDs is of type []string and already populated
	err := terminateInstances(collector.RunningInstances)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Instances terminated.")

	fmt.Println("Script completed.")
	return nil
}

func terminateInstances(instanceIDs []string) error {
	args := []string{"ec2", "terminate-instances", "--instance-ids"}
	// Append each instance ID as a separate element in the slice
	args = append(args, instanceIDs...)
	args = append(args, "--region", "us-east-1") // Specify the region if needed

	output, err := awsCLI(args...)
	if err != nil {
		return fmt.Errorf("error terminating instances: %v, output: %s", err, output)
	}
	fmt.Println("Terminate Instances Output:", output)
	return nil
}

func (collector *Collector) ReportStatsClient(req *datastruct.ClientStats, reply *datastruct.ReportStatsReply) error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	fmt.Println("Client Report Received")
	collector.RunStats[collector.CurrentTask].Clients = append(collector.RunStats[collector.CurrentTask].Clients, *req)
	reply.Status = true

	if len(collector.RunStats[collector.CurrentTask].Clients) == int(collector.RunTasks[collector.CurrentTask].TotalClients) && collector.RunStats[collector.CurrentTask].Auditor.TotalClients != 0 {
		// write collected data to a file
		WriteRevealInfoToDatabase(collector.RunStats)
		Cleanup(collector)

		if collector.CurrentTask == len(collector.RunTasks)-1 {
			// all task completed
			// exit
			//Delete the key pair
			fmt.Println("Deleting key pair...")
			if _, err := awsCLI("ec2", "delete-key-pair", "--key-name", collector.KeyName, "--region", "us-east-1"); err != nil {
				fmt.Println("Error deleting key pair:", err)
				return err
			}
			os.Remove(collector.KeyName + ".pem")
			fmt.Println("Key pair deleted.")
		} else {
			collector.CurrentTask += 1
			ExecuteCurrentTask(collector)
		}
	}
	return nil
}

func (collector *Collector) ReportStatsAuditor(req *datastruct.AuditorReport, reply *datastruct.ReportStatsReply) error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	fmt.Println("Auditor Report Received")
	collector.RunStats[collector.CurrentTask].Auditor = *req
	reply.Status = true

	if len(collector.RunStats[collector.CurrentTask].Clients) == int(collector.RunTasks[collector.CurrentTask].TotalClients) {
		// write collected data to a file
		WriteRevealInfoToDatabase(collector.RunStats)
		Cleanup(collector)

		if collector.CurrentTask == len(collector.RunTasks)-1 {
			// all task completed
			// exit
			//Delete the key pair
			fmt.Println("Deleting key pair...")
			if _, err := awsCLI("ec2", "delete-key-pair", "--key-name", collector.KeyName, "--region", "us-east-1"); err != nil {
				fmt.Println("Error deleting key pair:", err)
				return err
			}
			os.Remove(collector.KeyName + ".pem")
			fmt.Println("Key pair deleted.")
		} else {
			collector.CurrentTask += 1
			ExecuteCurrentTask(collector)
		}
	}
	return nil
}

func WriteRevealInfoToDatabase(db []datastruct.TestRun) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(db)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile("report.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}
