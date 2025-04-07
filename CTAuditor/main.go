package main

import (
	"CTLogchecker/AuditorApp/datastruct"
	"CTLogchecker/AuditorApp/services"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Auditor State:
// Registration of clients
// Initial reporting of entries for each client
// each client shuffle seqeuntially
// each client reveal
// client fault tolerance report

// this goes without saying: the protocol defaults to P256 curve
func main() {

	// the auditor needs to take arguments from the command line
	// total number of clients in a group
	// max number of clients that just can not reveal
	// the port number to listen on
	// the reveal threshold (optional for now)

	// os.Args provides access to raw command-line arguments.
	args := os.Args[1:] // Skip the program path at os.Args[0]

	if len(args) < 1 {
		fmt.Println("No argument provided.")
		return
	}

	// Try to convert the first argument to an integer.
	numClients, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Error: The first argument '%s' is not a valid integer.\n", args[0])
		return
	}

	clients_sit_out, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Error: The second argument '%s' is not a valid integer.\n", args[0])
		return
	}

	port := args[2]

	collector_address := args[3]

	threshold := uint32(numClients - clients_sit_out - 1)

	CTLogAuditor := new(services.CTLogCheckerAuditor)
	CTLogAuditor.CollectorAddress = collector_address
	CTLogAuditor.ShuffleDatabase = "database.json"
	CTLogAuditor.ZKDatabase = "zkdatabase.json"
	CTLogAuditor.TotalClients = uint32(numClients)
	CTLogAuditor.RevealThreshold = threshold
	CTLogAuditor.MaxSitOut = uint32(clients_sit_out)
	CTLogAuditor.CurrentState = services.Registration
	CTLogAuditor.CurrentClientCount = 0
	CTLogAuditor.CurrentShuffler = -1
	CTLogAuditor.CurrentInitialReporter = -1
	CTLogAuditor.Shamir_pieces = uint32(numClients - 1)
	CTLogAuditor.Shamir_curve = curves.P256()
	CTLogAuditor.CurrentFaultToleranceCount = 0

	// initialize PerClientCPU
	CTLogAuditor.PerClientCPU = []datastruct.AuditorClientCPUReport{}
	for i := 0; i < numClients; i++ {
		CTLogAuditor.PerClientCPU = append(CTLogAuditor.PerClientCPU, datastruct.AuditorClientCPUReport{ID: i})
	}
	err = services.InitializeDatabase(CTLogAuditor)
	if err != nil {
		log.Fatal("Error initializing database:", err)
	}
	// initialize the database files
	// Register the Arith type and its methods as an RPC service.
	rpc.Register(CTLogAuditor)

	// Serve HTTP connections on the RPC paths. This is a simple way to get RPC over HTTP.
	rpc.HandleHTTP()
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal("listen error:", err)
	}
	log.Printf("Serving RPC server on port " + port)
	http.Serve(listener, nil)

}
