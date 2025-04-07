package main

import (
	"fmt"
	"net/rpc"
	"os"
	"time"
)

type ShuffleInitRequest struct {
}

type ShuffleInitReply struct {
	Status bool
}

func main() {
	args := os.Args[1:]

	server_address := args[0]

	dial_successful := false

	var network_interface *rpc.Client
	var err error = nil
	for !dial_successful {
		network_interface, err = rpc.DialHTTP("tcp", server_address)
		if err != nil {
			fmt.Println(err)
			// time.Sleep(2 * time.Second)
		} else {
			dial_successful = true
		}
	}

	ping_successful := false

	req := ShuffleInitRequest{}

	var reply ShuffleInitReply

	fmt.Println(server_address)
	for !ping_successful {
		err = network_interface.Call("CTLogCheckerAuditor.PingStartShuffle", req, &reply)
		if err != nil || !reply.Status {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
		}
		if reply.Status {
			ping_successful = true
		}

	}

}
