package main

import (
	"CTCollector/datastruct"
	"CTCollector/services"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/exec"
	"time"
)

func main() {

	run_tasks := []datastruct.RunTask{}
	port := "80"
	// create a run task
	total_clients := []uint32{20, 40, 60, 80, 100}
	shufflers_keys_set := []uint32{1, 2, 5, 10, 15, 20}
	// total_clients := []uint32{100, 80, 60, 40, 20}
	sitout_percent := float64(0.1)
	for _, total_client := range total_clients {
		for _, shuffler_keys := range shufflers_keys_set {
			run_task := datastruct.RunTask{
				TotalClients:          total_client,
				MaxSitOut:             uint32(float64(total_client) * sitout_percent),
				Shuffler:              uint32(1),
				Shuffler_under_k_keys: shuffler_keys,
			}
			run_tasks = append(run_tasks, run_task)
		}

	}

	// fmt.Println(run_tasks)

	response, err := http.Get("https://api.ipify.org")
	if err != nil {
		fmt.Println("Error fetching IP: ", err)
		return
	}
	defer response.Body.Close()

	ip, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response: ", err)
		return
	}

	fmt.Println("Collector IP address:", string(ip))
	Collector := new(services.Collector)
	Collector.RunStats = []datastruct.TestRun{}
	Collector.RunTasks = run_tasks
	Collector.CurrentTask = 0
	Collector.CollectorIP = string(ip) + ":80"
	Collector.RunningInstances = []string{}
	keyName := "EC2KeyPair-" + time.Now().Format("20060102150405")
	region := "us-east-1"
	// Create a new EC2 Key Pair and save to a file
	keyMaterial, err := awsCLI("ec2", "create-key-pair", "--key-name", keyName, "--query", "KeyMaterial", "--output", "text", "--region", region)
	if err != nil {
		fmt.Println("Error creating key pair:", err)
		panic(err)
	}

	Collector.KeyName = keyName
	os.WriteFile(keyName+".pem", []byte(keyMaterial), 0400)

	rpc.Register(Collector)

	// Serve HTTP connections on the RPC paths. This is a simple way to get RPC over HTTP.
	rpc.HandleHTTP()
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	log.Printf("Serving RPC server on port " + port)
	// starts up the current task
	services.ExecuteCurrentTask(Collector)
	http.Serve(listener, nil)

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
