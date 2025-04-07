package services

import (
	"CTLogchecker/AuditorApp/datastruct"
	"CTLogchecker/AuditorApp/elgamal"
	"CTLogchecker/AuditorApp/safeprime"
	"CTLogchecker/AuditorApp/zklib"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/rpc"
	"os"
	"sync"
	"time"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Auditor State:
// Registration of clients
// Initial reporting of entries for each client
// each client shuffle seqeuntially
// each client reveal
// client fault tolerance report

type CTLogCheckerAuditor struct {
	ShuffleDatabase string
	ZKDatabase      string
	TotalClients    uint32
	RevealThreshold uint32
	MaxSitOut       uint32
	CurrentState    uint32
	/// dynamic parameters to be updated during the protocol
	CurrentClientCount     uint32
	CurrentInitialReporter int
	CurrentShuffler        int
	// CurrentRevealerCount       uint32
	Shamir_curve               *curves.Curve
	CurrentFaultToleranceCount uint32
	Shamir_pieces              uint32
	CalculatedEntries          [][][]byte
	CollectorAddress           string
	StartTime                  time.Time
	PerClientCPU               []datastruct.AuditorClientCPUReport
	MyIP                       string
	RevealZK                   []*datastruct.ZKRecords
	mu                         sync.Mutex // locking the thread such that all of the requests are handled sequentially
}

// protocol state
const (
	Registration = iota
	InitialReporting
	Shuffle
	Reveal
	FaultTolerance
	Completed
)

// Multiply takes two integers and returns the result of their multiplication.
// func (t *CTLogCheckerAuditor) Multiply(args *Args, reply *int) error {
// 	*reply = args.A * args.B
// 	return nil
// }

func InitializeDatabase(a *CTLogCheckerAuditor) error {
	// Check if the file already exists.
	_, err := os.Stat(a.ShuffleDatabase)

	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.ShuffleDatabase, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.ShuffleDatabase)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.ShuffleDatabase)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.ShuffleDatabase)
	} else {
		return err
	}

	data, err := ReadDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var database datastruct.Database
	if len(data) > 0 {
		err = json.Unmarshal(data, &database)
		if err != nil {
			return err
		}
	} else {
		database = datastruct.Database{
			Entries:         []*datastruct.ReportingEntry{},
			Shufflers_info:  []*datastruct.ShuffleRecords{},
			Decrypt_info:    []*datastruct.DecryptRecords{},
			Shuffle_PubKeys: []*datastruct.ShufflePubKeys{},
			SecreteShareMap: make(map[int][]*datastruct.SecreteSharePoint),
			FT_Info:         [][]datastruct.SecreteShareDecrypt{},
		}
	}

	WriteRevealInfoToDatabase(a, &database)

	// zk do it again
	_, err = os.Stat(a.ZKDatabase)

	// fmt.Println(a.ZKFileName)
	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.ZKDatabase, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.ZKDatabase)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.ZKDatabase)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.ZKDatabase)
	} else {
		return err
	}

	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var zkdatabase datastruct.ZKDatabase
	if len(data) > 0 {
		err = json.Unmarshal(zkdata, &zkdatabase)
		if err != nil {
			return err
		}
	} else {
		zkdatabase = datastruct.ZKDatabase{
			ZK_info: []*datastruct.ZKRecords{},
		}
	}

	WriteZKInfoToZKDatabase(a, &zkdatabase)

	return nil
}

// *** database reading and writing functions ***
func ReadDatabase(a *CTLogCheckerAuditor) ([]byte, error) {
	data, err := os.ReadFile(a.ShuffleDatabase)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func WriteRevealInfoToDatabase(certauditor *CTLogCheckerAuditor, db *datastruct.Database) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(db)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.ShuffleDatabase, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteZKInfoToZKDatabase(certauditor *CTLogCheckerAuditor, zkdb *datastruct.ZKDatabase) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdb)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.ZKDatabase, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func ReadZKDatabase(certauditor *CTLogCheckerAuditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.ZKDatabase)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// *** end of database reading and writing functions ***

// SERVICES *** client registration functions ***
func (certauditor *CTLogCheckerAuditor) RegisterClient(request *datastruct.RegistrationRequest, reponse *datastruct.RegistrationResponse) error {

	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	if certauditor.CurrentState != Registration {
		reponse.Status = false
		return nil
	}

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reponse.Status = false
		return err
	}
	var database datastruct.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v here?", err)
		reponse.Status = false
		return err
	}

	client_info := &datastruct.ShufflePubKeys{
		ID:       int(certauditor.CurrentClientCount),
		H_i:      request.H_shuffle,
		G_i:      request.G_shuffle,
		DH_Pub_H: request.DH_Pub_H,
		IP:       request.IP,
	}

	// check if the client has already registered
	for i := 0; i < len(database.Shuffle_PubKeys); i++ {
		if bytes.Equal(database.Shuffle_PubKeys[i].H_i, client_info.H_i) {
			reponse.Status = false
			return nil
		}
	}

	database.Shuffle_PubKeys = append(database.Shuffle_PubKeys, client_info)
	fmt.Println("Client registered successfully ", certauditor.CurrentClientCount)

	// update the current client count, and advance the state if all clients have registered
	certauditor.CurrentClientCount++
	if certauditor.CurrentClientCount == certauditor.TotalClients {
		certauditor.CurrentState = InitialReporting
		// generate the rsa params
		oddprimes := safeprime.GeneratePrimesWithout2(1 << 15)
		p, q, p_prime, q_prime, err := safeprime.GenerateGroupSubgroup(160, 15, 140, oddprimes)
		// fmt.Println(p, q, p_prime, q_prime)
		if err != nil {
			log.Fatalf("%v", err)
			return err
		}
		database.RSA_P = p
		database.RSA_Q = q
		database.RSA_subgroup_p_prime = p_prime
		database.RSA_subgroup_q_prime = q_prime
		fmt.Println("Found the group and subgroup primes.")
		certauditor.StartTime = time.Now()
	}

	WriteRevealInfoToDatabase(certauditor, &database)

	reponse.Status = true
	reponse.AssignedID = client_info.ID
	reponse.TotalClients = certauditor.TotalClients
	reponse.RevealThreshold = certauditor.RevealThreshold
	return nil
}

func (certauditor *CTLogCheckerAuditor) ReportInitialEntry(req *datastruct.InitalReportingRequest, reply *datastruct.InitalReportingReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	// essentially checks the current state of the protocol
	// and ensure that the no one is holding the lock
	if certauditor.CurrentState != InitialReporting {
		reply.Status = false
		return nil
	}

	if certauditor.CurrentInitialReporter != -1 {
		reply.Status = false
		return nil
	}

	start := time.Now()

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return err
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		reply.Status = false
		return err
	}

	// check if the client has already reported
	// quiet low prob of collision
	for i := 0; i < len(database.Entries); i++ {
		if bytes.Equal(database.Entries[i].Cert_times_h_r10[0], req.InitialEntry.Cert_times_h_r10[0]) {
			fmt.Println("Client already reported, OR Collision detected! can be bad")
			reply.Status = false
			return nil
		}
	}

	database.Entries = append(database.Entries, &req.InitialEntry)

	certauditor.CurrentInitialReporter = req.ShufflerID
	fmt.Println("Client reported successfully ", certauditor.CurrentInitialReporter)
	WriteRevealInfoToDatabase(certauditor, &database)

	reply.Status = true
	reply.Shuffle_PubKeys = database.Shuffle_PubKeys

	elapsed := time.Since(start)
	inital_report_time_seconds := elapsed.Seconds()

	certauditor.PerClientCPU[req.ShufflerID].InitialReportingTime = inital_report_time_seconds
	return nil
}

func (certauditor *CTLogCheckerAuditor) ReportInitialEntrySecreteShare(req *datastruct.InitalReportingSecreteSharingRequest, reply *datastruct.InitalReportingSecreteSharingReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	// essentially checks the current state of the protocol
	// and ensure that the the caller is holding the lock
	if certauditor.CurrentState != InitialReporting {
		reply.Status = false
		return nil
	}

	if certauditor.CurrentInitialReporter != req.ShufflerID {
		reply.Status = false
		return nil
	}

	start := time.Now()

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return err
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		reply.Status = false
		return err
	}

	// check if the client has already secrete shared
	_, exists := database.SecreteShareMap[req.ShufflerID]
	if exists {
		reply.Status = false
		// return nil
		panic("Client already reported")
	}

	database.SecreteShareMap[req.ShufflerID] = req.SecretePieces
	fmt.Println("Client secrete shared successfully ", req.ShufflerID)

	WriteRevealInfoToDatabase(certauditor, &database)

	if len(database.Entries) == int(certauditor.TotalClients) {
		fmt.Println("state changed to shuffle")
		certauditor.CurrentState = Shuffle
		// certauditor.CurrentShuffler = -1
	}

	// unhold the lock
	certauditor.CurrentInitialReporter = -1
	reply.Status = true

	elapsed := time.Since(start)
	secrete_share_time_seconds := elapsed.Seconds()

	certauditor.PerClientCPU[req.ShufflerID].SecreteSharing = secrete_share_time_seconds
	return nil
}

func (certauditor *CTLogCheckerAuditor) PingStartShuffle(req *datastruct.ShuffleInitRequest, reply *datastruct.ShuffleInitReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	if certauditor.CurrentState < Shuffle {
		fmt.Println("Ping Rejected")
		reply.Status = false
		return nil
	}

	if certauditor.CurrentState > Shuffle {
		fmt.Println("Ping Rejected")
		reply.Status = true
		return nil
	}

	fmt.Println("Ping Accepted")

	data, err := ReadDatabase(certauditor)

	if err != nil {
		reply.Status = false
		return nil
	}

	var database datastruct.Database

	err = json.Unmarshal(data, &database)

	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		reply.Status = false
		return nil
	}

	client_info := database.Shuffle_PubKeys

	for i := 0; i < int(certauditor.TotalClients); i++ {

		start_part1 := time.Now()
		client_ip := client_info[i].IP + ":80"
		// connect to the client

		client_connected := false
		var client *rpc.Client
		for !client_connected {
			client, err = rpc.Dial("tcp", client_ip)

			if err == nil {
				client_connected = true
			} else {
				log.Println(err)
				fmt.Println("dialing client failed. retrying")
			}
		}

		// read database
		data, err := ReadDatabase(certauditor)

		if err != nil {
			reply.Status = false
			panic(err)
			return nil
		}

		var database datastruct.Database

		err = json.Unmarshal(data, &database)

		if err != nil {
			log.Fatalf("Error unmarshaling the JSON: %v", err)
			reply.Status = false
			return nil
		}

		shuffle_request := datastruct.ShufflePhaseAuditorRequest{
			Database: database,
		}

		var shuffle_reply datastruct.ShufflePhaseAuditorReply

		shuffle_time_part1 := time.Since(start_part1).Seconds()
		// call the client shuffle

		client_took_call := false

		for !client_took_call {
			err = client.Call("Client.ClientShuffle", shuffle_request, &shuffle_reply)
			if err == nil {
				log.Println(err)
				client_took_call = true
			}
		}

		// fmt.Println(shuffle_reply)
		start_part2 := time.Now()
		// read the zkdatabase
		zkdata, err := ReadZKDatabase(certauditor)
		if err != nil {
			reply.Status = false
			panic(err)
			return nil
		}

		var zkdatabase datastruct.ZKDatabase
		err = json.Unmarshal(zkdata, &zkdatabase)
		if err != nil {
			log.Fatalf("Error unmarshaling the JSON: %v", err)
			reply.Status = false
			return nil
		}

		// verify the zk proof that the client provided
		uploaded_zk := shuffle_reply.ZKProofs

		// encryption check
		// checks sG=rG+cH
		proving_client := client_info[i].ID
		pubkeys_client, err := LocatePublicKeyWithID(proving_client, database.Shuffle_PubKeys)
		if err != nil {
			log.Fatalf("%v", err)
			reply.Status = false
			return nil
		}

		z1s := uploaded_zk.EncryptionProof.Z1s
		z2s := uploaded_zk.EncryptionProof.Z2s
		z3s := uploaded_zk.EncryptionProof.Z3s

		// fmt.Println(S_x)
		for i := 0; i < len(z1s); i++ {
			// first challenge
			X_z1, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.X_originals[i], z1s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			H_z2, err := elgamal.ECDH_bytes(pubkeys_client.H_i, z2s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			first_challenge_left_hand, err := elgamal.Encrypt(X_z1, H_z2)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			X_prime_c, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.X_primes[i], uploaded_zk.EncryptionProof.Cs[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}
			first_challenge_right_hand, err := elgamal.Encrypt(X_prime_c, uploaded_zk.EncryptionProof.I1s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			if !bytes.Equal(first_challenge_left_hand, first_challenge_right_hand) {
				fmt.Println("First challenge failed for client", proving_client)
				reply.Status = false
				return nil
			}
			// else {
			// 	fmt.Println("First challenge PASSED for client", proving_client.ID)
			// }

			// second challenge
			Y_z1, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.Y_originals[i], z1s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			H_z3, err := elgamal.ECDH_bytes(pubkeys_client.H_i, z3s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			second_challenge_left_hand, err := elgamal.Encrypt(Y_z1, H_z3)
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			Y_prime_c, err := elgamal.ECDH_bytes(uploaded_zk.EncryptionProof.Y_primes[i], uploaded_zk.EncryptionProof.Cs[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}
			second_challenge_right_hand, err := elgamal.Encrypt(Y_prime_c, uploaded_zk.EncryptionProof.I2s[i])
			if err != nil {
				log.Fatalf("%v", err)
				reply.Status = false
				return nil
			}

			if !bytes.Equal(second_challenge_left_hand, second_challenge_right_hand) {
				fmt.Println("Second challenge failed for client", proving_client)
				reply.Status = false
				return nil
			}
			// else {
			// 	fmt.Println("Second challenge PASSED for client", proving_client.ID)
			// }

		}

		fmt.Println("ZK Proof for encryption is verified for client ", proving_client)
		//********* shuffle check
		n := len(uploaded_zk.ShuffleProof.EntriesAfterShuffle)
		gs := uploaded_zk.ShuffleProof.RSA_subgroup_generators
		N := new(big.Int).Mul(database.RSA_P, database.RSA_Q)
		// first check
		ts := uploaded_zk.ShuffleProof.ChallengesLambda
		/// sum up fs and check if it is equal to sum of ts
		sum := big.NewInt(0)

		fs := uploaded_zk.ShuffleProof.Fs
		small_z := uploaded_zk.ShuffleProof.SmallZ
		Z_ks := uploaded_zk.ShuffleProof.Z_ks
		Z_prime := uploaded_zk.ShuffleProof.Z_prime
		for _, f := range fs {
			sum.Add(sum, f)
		}
		sum_ts := big.NewInt(0)
		for _, t := range ts {
			sum_ts.Add(sum_ts, zklib.SetBigIntWithBytes(t))
		}
		// fmt.Println("Sum of fs:", sum)
		// fmt.Println("Sum of ts:", sum_ts)
		if sum.Cmp(sum_ts) == 0 {
			// fmt.Println("First Test PASSED!!!!!!!!!Sum of fs is equal to sum of ts")
		} else {
			fmt.Println("Sum of fs is not equal to sum of ts")
			reply.Status = false
			return nil
		}

		// second check
		// calculate f_delta
		f_delta := big.NewInt(0)
		// sum of f squared
		for _, f := range fs {
			f_delta.Add(f_delta, new(big.Int).Mul(f, f))
		}
		// minus sum of ts squared
		for _, t := range ts {
			f_delta.Sub(f_delta, new(big.Int).Mul(zklib.SetBigIntWithBytes(t), zklib.SetBigIntWithBytes(t)))
		}

		/// conducting second check
		second_condition_right_hand_side := zklib.Generate_commitment(gs, fs, f_delta, small_z.Bytes(), N)
		// fmt.Print("second_condition_right_hand_side ")
		// fmt.Println(second_condition_right_hand_side)
		second_condition_left_hand_side := new(big.Int).Set(uploaded_zk.ShuffleProof.Commitments[n])
		for i := 0; i < n; i++ {
			second_condition_left_hand_side = new(big.Int).Mul(second_condition_left_hand_side, new(big.Int).Exp(uploaded_zk.ShuffleProof.Commitments[i], zklib.SetBigIntWithBytes(ts[i]), N))
		}
		second_condition_left_hand_side = new(big.Int).Mod(second_condition_left_hand_side, N)

		// fmt.Print("second_condition_left_hand_side ")
		// fmt.Println(second_condition_left_hand_side)
		// compare the two sides
		if second_condition_left_hand_side.Cmp(second_condition_right_hand_side) == 0 {
			// fmt.Println("Second Test PASSED!!!!!!!!!")
		} else {
			fmt.Println("Second Test failed. they are not equal! Failed???????")
			reply.Status = false
			return nil
		}

		// third check for the entries **** hardest part brutal
		// k means the index for individual pieces of the entry
		for k := 0; k < len(uploaded_zk.ShuffleProof.EntriesAfterShuffle[0]); k++ {
			third_check_left_hand_side := elgamal.ReturnInfinityPoint()
			for i := 0; i < n; i++ {
				C_i := uploaded_zk.ShuffleProof.EntriesAfterShuffle[i][k]
				C_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(C_i, fs[i].Bytes())
				if err != nil {
					panic(err)
				}
				// check if fs[i] is negative
				if fs[i].Cmp(big.NewInt(0)) < 0 {
					// fmt.Println("detected negative fs[i]")
					C_i_f_i, err = elgamal.ReturnNegative(C_i_f_i)
					if err != nil {
						panic(err)
					}
				}
				third_check_left_hand_side, err = elgamal.Encrypt(third_check_left_hand_side, C_i_f_i)
				if err != nil {
					panic(err)
				}
			}

			third_check_right_hand_side := uploaded_zk.ShuffleProof.Big_Vs[k]
			for i := 0; i < n; i++ {
				c_i := uploaded_zk.ShuffleProof.EntriesBeforeShuffle[i][k]
				c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(c_i, ts[i])
				if err != nil {
					panic(err)
				}
				third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, c_i_lambda_i)
			}
			// find the public key of the shuffler
			for i := 0; i < len(uploaded_zk.ShuffleProof.Updated_Shufflers_info); i++ {
				updated_shufflers := uploaded_zk.ShuffleProof.Updated_Shufflers_info[i]
				shuffler_keys, err := LocatePublicKeyWithID(updated_shufflers.ID, database.Shuffle_PubKeys)
				if err != nil {
					panic(err)
				}
				encrypted_one_with_Z_k, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_ks[i])
				if err != nil {
					panic(err)
				}
				third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, encrypted_one_with_Z_k)
				if err != nil {
					panic(err)
				}
			}

			// compare the two sides
			if !bytes.Equal(third_check_left_hand_side, third_check_right_hand_side) {
				fmt.Println("Third Test FAILED????????", k)
				reply.Status = false
				return nil
			}
		}
		// fmt.Println("Third Test concerning the cyphertext shuffling PASSED!!!!!!!!!")

		// fourth check for tag X
		fourth_condition_left_hand_side := elgamal.ReturnInfinityPoint()

		for i := 0; i < n; i++ {
			T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(uploaded_zk.ShuffleProof.X_primes_encrypted_and_permutated_tagX[i], fs[i].Bytes())
			if err != nil {
				panic(err)
			}
			// check if fs[i] is negative
			if fs[i].Cmp(big.NewInt(0)) < 0 {
				// fmt.Println("detected negative fs[i]")
				T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
				if err != nil {
					panic(err)
				}
			}
			fourth_condition_left_hand_side, err = elgamal.Encrypt(fourth_condition_left_hand_side, T_i_f_i)
			if err != nil {
				panic(err)
			}
		}
		fourth_condition_right_hand_side := uploaded_zk.ShuffleProof.V_prime_X
		// find the public key of the shuffler
		shuffler_keys, err := LocatePublicKeyWithID(uploaded_zk.ShufflerID, database.Shuffle_PubKeys)

		if err != nil {
			panic(err)
		}
		encrypted_one_with_Z_prime, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(shuffler_keys.H_i, Z_prime.Bytes())
		// fmt.Println(shuffler_keys.H_i)
		if err != nil {
			panic(err)
		}
		fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, encrypted_one_with_Z_prime)
		if err != nil {
			panic(err)
		}
		lambdas := ts
		tags_before_shuffle := uploaded_zk.EncryptionProof.X_primes
		for i := 0; i < n; i++ {
			small_c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle[i], lambdas[i])
			if err != nil {
				panic(err)
			}
			fourth_condition_right_hand_side, err = elgamal.Encrypt(fourth_condition_right_hand_side, small_c_i_lambda_i)
			if err != nil {
				panic(err)
			}
		}
		// compare the two sides
		if bytes.Equal(fourth_condition_left_hand_side, fourth_condition_right_hand_side) {
			// fmt.Println("Fourth Test PASSED!!!!!!!!!")
		} else {
			fmt.Println("Fourth Test FAILED????????")
			reply.Status = false
			return nil
		}

		// fitfh check for tag Y
		fifth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
		// if err != nil {
		// 	panic(err)
		// }
		for i := 0; i < n; i++ {
			T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(uploaded_zk.ShuffleProof.Y_primes_encrypted_and_permutated_tagY[i], fs[i].Bytes())
			if err != nil {
				panic(err)
			}
			// check if fs[i] is negative
			if fs[i].Cmp(big.NewInt(0)) < 0 {
				// fmt.Println("detected negative fs[i]")
				T_i_f_i, err = elgamal.ReturnNegative(T_i_f_i)
				if err != nil {
					panic(err)
				}
			}
			fifth_condition_left_hand_side, err = elgamal.Encrypt(fifth_condition_left_hand_side, T_i_f_i)
			if err != nil {
				panic(err)
			}
		}
		fifth_condition_right_hand_side := uploaded_zk.ShuffleProof.V_prime_Y

		fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, encrypted_one_with_Z_prime)
		if err != nil {
			panic(err)
		}
		// lambdas := ts
		tags_before_shuffle_Y := uploaded_zk.EncryptionProof.Y_primes
		for i := 0; i < n; i++ {
			small_C_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(tags_before_shuffle_Y[i], lambdas[i])
			if err != nil {
				panic(err)
			}
			fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, small_C_i_lambda_i)
			if err != nil {
				panic(err)
			}
		}
		// compare the two sides
		if bytes.Equal(fifth_condition_left_hand_side, fifth_condition_right_hand_side) {
			// fmt.Println("Fifth Test PASSED!!!!!!!!!")
		} else {
			fmt.Println("Fifth Test FAILED????????")
			reply.Status = false
			return nil
		}
		// decryption check

		// need to perform a check to ensure that zk proof checks out

		zkdatabase.ZK_info = append(zkdatabase.ZK_info, &uploaded_zk)

		database = shuffle_reply.Database

		WriteRevealInfoToDatabase(certauditor, &database)

		// write the zkdatabase

		WriteZKInfoToZKDatabase(certauditor, &zkdatabase)

		if len(database.Shufflers_info) == int(certauditor.TotalClients) {
			certauditor.CurrentState = Reveal
			// read ZK database
			zkdata, err := ReadZKDatabase(certauditor)
			if err != nil {
				reply.Status = false
				return nil
			}

			var zkdatabase datastruct.ZKDatabase
			err = json.Unmarshal(zkdata, &zkdatabase)
			if err != nil {
				log.Fatalf("Error unmarshaling the JSON: %v", err)
				reply.Status = false
				return nil
			}

			for i := 0; i < len(zkdatabase.ZK_info); i++ {
				if i != len(zkdatabase.ZK_info)-1 {
					zkdatabase.ZK_info[i].ShuffleProof.EntriesAfterShuffle = nil
				}
			}

			certauditor.RevealZK = zkdatabase.ZK_info
		}

		shuffle_time_part2 := time.Since(start_part2).Seconds()

		certauditor.PerClientCPU[proving_client].ShuffleTime = shuffle_time_part1 + shuffle_time_part2

		fmt.Println("client shuffled successfully", proving_client)
		client.Close()
	}
	reply.Status = true
	fmt.Println("Shuffling done")
	if certauditor.CurrentState == Reveal {
		fmt.Println("State changed to Reveal")
	} else {
		panic("State not changed to Reveal, bad")
	}
	return nil

}

func LocatePublicKeyWithID(clientID int, ShufflerPublicKeys []*datastruct.ShufflePubKeys) (*datastruct.ShufflePubKeys, error) {
	for i := 0; i < len(ShufflerPublicKeys); i++ {
		if clientID == ShufflerPublicKeys[i].ID {
			return ShufflerPublicKeys[i], nil
		}
	}
	return nil, errors.New("Shuffler Public Key Not Found")
}

func (certauditor *CTLogCheckerAuditor) RevealPhaseClientAcquireDatabase(req *datastruct.RevealPhaseAcquireDatabaseRequest, reply *datastruct.RevealPhaseAcquireDatabaseReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	start := time.Now()
	// essentially checks the current state of the protocol
	// and ensure that the the caller is holding the lock
	if certauditor.CurrentState != Reveal {
		reply.Status = false
		return nil
	}

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return nil
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		reply.Status = false
		return nil
	}

	reply.ZK_info = certauditor.RevealZK

	reply.Database = database
	reply.Status = true

	elapsed := time.Since(start)
	reveal_acquire_database_time_seconds := elapsed.Seconds()

	certauditor.PerClientCPU[req.ShufflerID].RevealTime += reveal_acquire_database_time_seconds
	return nil
}

func LocateShuffleOrderWithID(clientID int, Shufflers []*datastruct.ShuffleRecords) (int, error) {
	for i := 0; i < len(Shufflers); i++ {
		if clientID == Shufflers[i].ID {
			return i, nil
		}
	}
	return -1, errors.New("Shuffle order not found")
}

func (certauditor *CTLogCheckerAuditor) RevealPhaseClientRevealResult(req *datastruct.RevealPhaseReportRevealRequest, reply *datastruct.RevealPhaseReportRevealReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	if certauditor.CurrentState != Reveal {
		reply.Status = false
		return nil
	}

	start := time.Now()
	// potentially more checks
	// read database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return nil
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		reply.Status = false
		return nil
	}

	database.Decrypt_info = append(database.Decrypt_info, &req.RevealRecords)
	WriteRevealInfoToDatabase(certauditor, &database)

	reveal_time_seconds := time.Since(start).Seconds()
	certauditor.PerClientCPU[req.ShufflerID].RevealTime += reveal_time_seconds

	if len(database.Decrypt_info) == int(certauditor.TotalClients-certauditor.MaxSitOut) {
		if certauditor.MaxSitOut > 0 {
			certauditor.CurrentState = FaultTolerance
		} else {
			certauditor.CurrentState = Completed
			/// calculate the entries

			reveal_calculation_start := time.Now()
			result := CalculateEntries(certauditor)

			reveal_calculation_time := time.Since(reveal_calculation_start).Seconds()

			total_time := time.Since(certauditor.StartTime).Seconds()

			for i := 0; i < int(certauditor.TotalClients); i++ {
				certauditor.PerClientCPU[i].RevealTime += reveal_calculation_time / float64(certauditor.TotalClients)
			}

			certauditor.CalculatedEntries = result
			// report to the collector
			collector_interface, err := rpc.DialHTTP("tcp", certauditor.CollectorAddress)

			if err != nil {
				log.Fatal("dialing:", err)
			}

			var report_stats_reply datastruct.ReportStatsReply
			report_stats_req := datastruct.AuditorReport{}

			report_stats_req.CalculatedEntries = certauditor.CalculatedEntries
			report_stats_req.TotalClients = certauditor.TotalClients
			report_stats_req.MaxSitOut = certauditor.MaxSitOut
			report_stats_req.TotalRunTime = total_time
			report_stats_req.PerClientCPU = certauditor.PerClientCPU
			status_reported := false

			for !status_reported {
				err = collector_interface.Call("Collector.ReportStatsAuditor", report_stats_req, &report_stats_reply)
				if err != nil {
					log.Fatal("arith error:", err)
				}
				if report_stats_reply.Status {
					status_reported = true
				}
			}
		}

	}
	reply.Status = true
	return nil
}

func (certauditor *CTLogCheckerAuditor) FaultTolerancePhaseAcquireDatabase(req *datastruct.FaultTolerancePhaseAcquireDatabaseRequest, reply *datastruct.FaultTolerancePhaseAcquireDatabaseReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	// essentially checks the current state of the protocol
	// and ensure that the the caller is holding the lock

	start := time.Now()

	if certauditor.CurrentState == Completed {
		reply.Status = true
		reply.FTNeeded = false
		return nil
	}

	if certauditor.CurrentState != FaultTolerance {
		reply.Status = false
		return nil
	}

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return err
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		reply.Status = false
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}

	reply.FTNeeded = true
	reply.Status = true
	reply.Database = database

	n := int(certauditor.TotalClients)
	clients := make([]int, n)
	for i := 0; i < n; i++ {
		clients[i] = i
	}

	for j := 0; j < len(database.Decrypt_info); j++ {
		if contains(clients, database.Decrypt_info[j].ShufflerID) {
			clients = remove(clients, database.Decrypt_info[j].ShufflerID)
		}
	}

	reply.AbsentClients = clients
	// fmt.Println(clients)

	elapsed := time.Since(start).Seconds()

	certauditor.PerClientCPU[req.ShufflerID].FaultToleranceTime += elapsed

	return nil
}

// contains checks if a slice contains a specific integer
func contains(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// remove removes a specific integer from a slice if it exists
func remove(slice []int, value int) []int {
	for i, v := range slice {
		if v == value {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func (certauditor *CTLogCheckerAuditor) FaultTolerancePhaseReportResult(req *datastruct.FaultTolerancePhaseReportResultRequest, reply *datastruct.FaultTolerancePhaseReportResultReply) error {
	certauditor.mu.Lock()
	defer certauditor.mu.Unlock()

	// essentially checks the current state of the protocol
	// and ensure that the the caller is holding the lock
	if certauditor.CurrentState != FaultTolerance {
		reply.Status = false
		return nil
	}

	start := time.Now()

	data, err := ReadDatabase(certauditor)
	if err != nil {
		reply.Status = false
		return err
	}

	var database datastruct.Database
	err = json.Unmarshal(data, &database)
	if err != nil {
		reply.Status = false
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}

	database.FT_Info = append(database.FT_Info, req.DecryptedPieces)

	reply.Status = true
	WriteRevealInfoToDatabase(certauditor, &database)

	ft_time := time.Since(start).Seconds()

	certauditor.PerClientCPU[req.ShufflerID].FaultToleranceTime += ft_time

	if len(database.FT_Info) == int(certauditor.TotalClients-certauditor.MaxSitOut) {
		certauditor.CurrentState = Completed
		/// calculate the entries

		reveal_calculation_start := time.Now()

		result := CalculateEntries(certauditor)

		// fmt.Println(result)
		if certauditor.MaxSitOut > 0 {
			// fault tolerance kick in
			fmt.Println("Fault Tolerant Kicking in")
			for i := 0; i < int(certauditor.MaxSitOut); i++ {
				fault_tolerant_results := []datastruct.SecreteShareDecrypt{}
				for j := 0; j < len(database.FT_Info); j++ {
					fault_tolerant_results = append(fault_tolerant_results, database.FT_Info[j][i])
				}
				// may need to check whether the client number required passed the threshold
				//compute the new result after this round of fault tolerance
				var err error
				result, err = CalculateEntriesForFaultToleranceOfOneClient(certauditor, result, fault_tolerant_results)
				if err != nil {
					// fmt.Println(err)
					panic(err)
				}
			}
		}
		reveal_calculation_time := time.Since(reveal_calculation_start).Seconds()

		for i := 0; i < int(certauditor.TotalClients); i++ {
			certauditor.PerClientCPU[i].RevealTime += reveal_calculation_time / float64(certauditor.TotalClients)
		}
		// for j := 0; j < len(result); j++ {
		// 	extracted_cert, _ := ExtractData(result[j])
		// 	fmt.Println(extracted_cert)
		// }
		total_time := time.Since(certauditor.StartTime).Seconds()
		certauditor.CalculatedEntries = result

		// report to the collector
		collector_interface, err := rpc.DialHTTP("tcp", certauditor.CollectorAddress)

		if err != nil {
			log.Fatal("dialing:", err)
		}

		var report_stats_reply datastruct.ReportStatsReply
		report_stats_req := datastruct.AuditorReport{}

		report_stats_req.CalculatedEntries = certauditor.CalculatedEntries
		report_stats_req.TotalClients = certauditor.TotalClients
		report_stats_req.MaxSitOut = certauditor.MaxSitOut
		report_stats_req.TotalRunTime = total_time
		report_stats_req.PerClientCPU = certauditor.PerClientCPU

		status_reported := false

		for !status_reported {
			err = collector_interface.Call("Collector.ReportStatsAuditor", report_stats_req, &report_stats_reply)
			if err != nil {
				log.Fatal("arith error:", err)
			}
			if report_stats_reply.Status {
				status_reported = true
			}
		}
	}

	return nil
}

// extract the certificate out of these points
func ExtractData(segments [][]byte) ([]byte, error) {
	if len(segments) != 9 {
		return nil, errors.New("there must be exactly 9 segments")
	}

	var data []byte
	for i, segment := range segments {
		if len(segment) != 33 {
			return nil, errors.New("segment must be 33 bytes long")
		}
		if i == 8 {
			// Last segment with 1 byte of sign, 1 byte of padding, 24 bytes of data, and 7 bytes of random data
			data = append(data, segment[2:26]...)
		} else {
			// normal segment with 1 byte of sign, 1 byte of padding, 29 bytes of data, and 2 bytes of hash of next segment
			data = append(data, segment[2:31]...)
		}

	}
	return data, nil
}

func CalculateEntries(certauditor *CTLogCheckerAuditor) [][][]byte {
	/// reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database datastruct.Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	res := [][][]byte{}
	// decrypting
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
		for j := 0; j < len(database.Decrypt_info); j++ {
			res[i], err = DecryptSegments(database.Decrypt_info[j].Keys[i], res[i])
			if err != nil {
				log.Fatalf("%v", err)
				return nil
			}
		}
	}
	return res
}

func DecryptSegments(SharedSecret []byte, segments [][]byte) ([][]byte, error) {
	// Decrypt the segments
	decryptedSegments := make([][]byte, len(segments))
	for i, segment := range segments {
		decryptedSegment, err := elgamal.Decrypt(SharedSecret, segment)
		if err != nil {
			return nil, err
		}
		decryptedSegments[i] = decryptedSegment
	}

	return decryptedSegments, nil
}

func CalculateEntriesForFaultToleranceOfOneClient(CertAuditor *CTLogCheckerAuditor, result [][][]byte, fault_tolerant_results []datastruct.SecreteShareDecrypt) ([][][]byte, error) {
	// the laranagian method, brutal
	// construct a map and a tag array to enable better access
	list_of_tags := make([]uint32, len(fault_tolerant_results))
	for i := 0; i < len(list_of_tags); i++ {
		// result[i]
		list_of_tags[i] = fault_tolerant_results[i].Tag
	}
	// fmt.Println(list_of_tags)
	// recreate the shamir and calculate coefficients
	scheme, _ := sharing.NewShamir(CertAuditor.RevealThreshold, CertAuditor.Shamir_pieces, CertAuditor.Shamir_curve)
	lagrange_map, err := scheme.LagrangeCoeffs(list_of_tags)
	if err != nil {
		log.Fatalf("%v", err)
		return nil, err
	}
	// apply larangian to every entry
	// fmt.Println(lagrange_map)
	/// add up first
	calculated_res := [][]byte{}
	for i := 0; i < len(fault_tolerant_results); i++ {
		// result[i]
		lcoef := lagrange_map[fault_tolerant_results[i].Tag].Bytes()
		for j := 0; j < len(result); j++ {
			d_lambda, err := elgamal.ECDH_bytes(fault_tolerant_results[i].DecryptPieces[j], lcoef)
			if err != nil {
				log.Fatalf("%v", err)
				return nil, err
			}
			if i == 0 {
				calculated_res = append(calculated_res, d_lambda)
			} else {
				calculated_res[j], err = elgamal.Encrypt(calculated_res[j], d_lambda)
				if err != nil {
					log.Fatalf("%v", err)
					return nil, err
				}
			}
		}
	}
	for k := 0; k < len(result); k++ {
		result[k], _ = DecryptSegments(calculated_res[k], result[k])
	}
	return result, err
}
