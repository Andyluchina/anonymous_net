package auditor

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/elgamal"
	"web_cert_reporting_faultTolerantChainingZK_NonInteractive/zklib"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

type Client struct {
	ID             int
	ReportingKey   *ecdh.PrivateKey
	ShuffleKey     *ecdh.PrivateKey
	ReportingValue []byte
	Curve          ecdh.Curve
	G_report       []byte /// init point needs to be different for every client
	H_report       []byte
	G_shuffle      []byte /// init point needs to be different for every client
	H_shuffle      []byte
	DH_Pub_H       []byte /// pub key for secrete sharing
	DH_Pub_private []byte
	InitialG_ri0   []byte
}

// h = g^x where x is the private key
type ReportingEntry struct {
	Cert_times_h_r10 [][]byte
	// G_ri0            []byte
	H_r_i1    []byte
	G_ri1     []byte
	Shufflers [][]byte
}

type Database struct {
	Entries         []*ReportingEntry
	Shufflers_info  []*ShuffleRecords
	Decrypt_info    []*DecryptRecords
	Shuffle_PubKeys []*ShufflePubKeys
	SecreteShareMap map[int][]*SecreteSharePoint
	// ZK_info         []*ZKRecords
}

type ZKDatabase struct {
	ZK_info []*ZKRecords
}

type ZKRecords struct {
	ShufflerID      int
	EncryptionProof EcryptionProofRecord
	ShuffleProof    ShuffleProofRecord
	DecryptionProof DecryptionProofRecord
}

type DecryptionProofRecord struct {
	RG_X       [][]byte
	RG_Y       [][]byte
	Challenges [][]byte
	Ss_X       [][]byte
	Ss_Y       [][]byte
}

type EcryptionProofRecord struct {
	X_originals [][]byte
	Y_originals [][]byte
	X_primes    [][]byte
	Y_primes    [][]byte
	I1s         [][]byte
	I2s         [][]byte
	Cs          [][]byte
	Z1s         [][]byte
	Z2s         [][]byte
	Z3s         [][]byte
}

type ShuffleProofRecord struct {
	// recorded before shuffle
	EntriesBeforeShuffle [][][]byte
	// RSA public params
	RSA_P                   *big.Int
	RSA_Q                   *big.Int
	RSA_subgroup_p_prime    *big.Int
	RSA_subgroup_q_prime    *big.Int
	RSA_subgroup_generators []*big.Int
	// commitment
	EntriesAfterShuffle                    [][][]byte
	X_primes_encrypted_and_permutated_tagX [][]byte
	Y_primes_encrypted_and_permutated_tagY [][]byte
	Commitments                            []*big.Int
	Big_Vs                                 [][]byte
	V_prime_X                              []byte
	V_prime_Y                              []byte
	Updated_Shufflers_info                 []*ShuffleRecords
	//challenges
	ChanllengesLambda [][]byte
	// Responses
	Fs      []*big.Int
	SmallZ  *big.Int
	Z_ks    [][]byte
	Z_prime *big.Int
}

type ShuffleRecords struct {
	ID int
	// H_i []byte
	// G_i []byte
}

type SecreteSharePoint struct {
	Intended_Client int
	Tag             uint32
	Encrypted_y     []byte
}

type ShufflePubKeys struct {
	ID       int
	H_i      []byte
	G_i      []byte
	DH_Pub_H []byte
}

type DecryptRecords struct {
	ShufflerID int
	Keys       [][]byte
}

type Auditor struct {
	FileName         string
	ZKFileName       string
	Curve            ecdh.Curve
	Shamir_pieces    uint32
	Shamir_threshold uint32
	Shamir_curve     *curves.Curve
}

type SecreteShareDecrypt struct {
	Tag           uint32
	DecryptPieces [][]byte
}

// NewAuditor creates a new Auditor instance
func NewAuditor(fileName string, zkfileName string, c ecdh.Curve, shamir_p uint32, shamir_t uint32, shamir_curve *curves.Curve) *Auditor {
	return &Auditor{FileName: fileName, ZKFileName: zkfileName, Curve: c, Shamir_pieces: shamir_p, Shamir_threshold: shamir_t, Shamir_curve: shamir_curve}
}

func (a *Auditor) InitializeDatabase() error {
	// Check if the file already exists.
	_, err := os.Stat(a.FileName)

	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.FileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.FileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.FileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.FileName)
	} else {
		return err
	}

	data, err := ReadDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var database Database
	if len(data) > 0 {
		err = json.Unmarshal(data, &database)
		if err != nil {
			return err
		}
	} else {
		database = Database{
			Entries:         []*ReportingEntry{},
			Shufflers_info:  []*ShuffleRecords{},
			Decrypt_info:    []*DecryptRecords{},
			Shuffle_PubKeys: []*ShufflePubKeys{},
			SecreteShareMap: make(map[int][]*SecreteSharePoint),
		}
	}

	WriteRevealInfoToDatabase(a, &database)

	// zk do it again
	_, err = os.Stat(a.ZKFileName)

	// fmt.Println(a.ZKFileName)
	if err == nil {
		// File exists, clear its contents
		err = os.Truncate(a.ZKFileName, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Cleared contents of %s\n", a.ZKFileName)
	} else if os.IsNotExist(err) {
		// File doesn't exist, create it.
		file, err := os.Create(a.ZKFileName)
		if err != nil {
			return err
		}
		defer file.Close()
		fmt.Printf("Created %s\n", a.ZKFileName)
	} else {
		return err
	}

	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		return err
	}

	// Unmarshal the byte slice into variable
	var zkdatabase ZKDatabase
	if len(data) > 0 {
		err = json.Unmarshal(zkdata, &zkdatabase)
		if err != nil {
			return err
		}
	} else {
		zkdatabase = ZKDatabase{
			ZK_info: []*ZKRecords{},
		}
	}

	WriteZKInfoToZKDatabase(a, &zkdatabase)

	return nil
}

func ReadDatabase(certauditor *Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.FileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ReadZKDatabase(certauditor *Auditor) ([]byte, error) {
	data, err := os.ReadFile(certauditor.ZKFileName)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func ReportPhase_AppendEntryToDatabase(certauditor *Auditor, entry *ReportingEntry) error {
	// Read the existing data from the database file
	existingData, err := ReadDatabase(certauditor)
	if err != nil {
		return err
	}

	// Unmarshal the existing data into a slice of CipherText
	var databaseCiphertexts Database
	err = json.Unmarshal(existingData, &databaseCiphertexts)
	if err != nil {
		return err
	}

	// Append the new ciphertexts to the existing array
	databaseCiphertexts.Entries = append(databaseCiphertexts.Entries, entry)

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(databaseCiphertexts)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.FileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteRevealInfoToDatabase(certauditor *Auditor, db *Database) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(db)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.FileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func WriteZKInfoToZKDatabase(certauditor *Auditor, zkdb *ZKDatabase) error {
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdb)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}

	// Write the updated data to the file
	err = os.WriteFile(certauditor.ZKFileName, updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalculateEntries(certauditor *Auditor) [][][]byte {
	/// reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

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

// func CalculateEntries_one_client(certauditor *Auditor, client *Client, database *Database) [][]byte {

// 	res := [][]byte{}
// 	// decrypting
// 	for i := 0; i < len(database.Entries); i++ {
// 		for j := 0; j < len(database.Decrypt_info); j++ {
// 			if database.Decrypt_info[j].ShufflerID == client.ID {
// 				res = append(res, database.Decrypt_info[j].Keys[i])
// 			}
// 		}
// 	}
// 	return res
// }

func MakeACopyOfDatabase(certauditor *Auditor) error {
	// / reading the database
	data, err := ReadDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile("database_copy.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func MakeACopyOfZKDatabase(certauditor *Auditor) error {
	// / reading the database
	data, err := ReadZKDatabase(certauditor)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}
	var database ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return nil
	}

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(database)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile("zkdatabase_copy.json", updatedData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func CalculateEntriesForFaultToleranceOfOneClient(CertAuditor *Auditor, result [][][]byte, fault_tolerant_results []*SecreteShareDecrypt) ([][][]byte, error) {
	// the laranagian method, brutal
	// construct a map and a tag array to enable better access
	list_of_tags := make([]uint32, len(fault_tolerant_results))
	for i := 0; i < len(list_of_tags); i++ {
		// result[i]
		list_of_tags[i] = fault_tolerant_results[i].Tag
	}
	// fmt.Println(list_of_tags)
	// recreate the shamir and calculate coefficients
	scheme, _ := sharing.NewShamir(CertAuditor.Shamir_threshold, CertAuditor.Shamir_pieces, CertAuditor.Shamir_curve)
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

//// ZERO KNOWLEDGE PROOF ***********

// / func prepopulate the ZK info to keep a record
func (a *Auditor) PopulateZKInfo(shuffling_client *Client) error {

	data, err := ReadDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}

	// / reading the zkdatabase
	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}
	var zkdatabase ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(zkdata, &zkdatabase)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return err
	}

	/// prepopulate the encryption proof
	zkdatabase.ZK_info = append(zkdatabase.ZK_info, &ZKRecords{
		ShufflerID: shuffling_client.ID,
		EncryptionProof: EcryptionProofRecord{
			X_originals: ExtractH_r_i1sFromEntries(&database),
			Y_originals: ExtractG_ri1sFromEntries(&database),
			Z1s:         [][]byte{},
			Z2s:         [][]byte{},
			Z3s:         [][]byte{},
			X_primes:    [][]byte{},
			Y_primes:    [][]byte{},
			I1s:         [][]byte{},
			I2s:         [][]byte{},
			Cs:          [][]byte{},
		},
		ShuffleProof: ShuffleProofRecord{
			EntriesBeforeShuffle:                   ExtractCertsFromEntries(&database),
			EntriesAfterShuffle:                    [][][]byte{},
			X_primes_encrypted_and_permutated_tagX: [][]byte{},
			Y_primes_encrypted_and_permutated_tagY: [][]byte{},
			Commitments:                            []*big.Int{},
			Big_Vs:                                 [][]byte{},
			V_prime_X:                              []byte{},
			V_prime_Y:                              []byte{},
			ChanllengesLambda:                      [][]byte{},
			Fs:                                     []*big.Int{},
			SmallZ:                                 new(big.Int),
			Z_ks:                                   [][]byte{},
			Z_prime:                                new(big.Int),
			Updated_Shufflers_info:                 []*ShuffleRecords{},
		},
		DecryptionProof: DecryptionProofRecord{
			RG_X:       [][]byte{},
			RG_Y:       [][]byte{},
			Challenges: [][]byte{},
			Ss_X:       [][]byte{},
			Ss_Y:       [][]byte{},
		},
	})

	/// prepopulate the shuffle proof groth and Lu

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdatabase)
	// fmt.Println(updatedData)
	if err != nil {
		return err
	}
	// Write the updated data to the file
	err = os.WriteFile(a.ZKFileName, updatedData, 0644)
	if err != nil {
		return err
	}

	MakeACopyOfZKDatabase(a)

	return nil
}

func ExtractEntriesFromEntries(database *Database) [][][]byte {
	res := [][][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
	}
	return res
}

func ExtractH_r_i1sFromEntries(database *Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].H_r_i1)
	}
	return res
}

func ExtractCertsFromEntries(database *Database) [][][]byte {
	res := [][][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].Cert_times_h_r10)
	}
	return res
}

func ExtractG_ri1sFromEntries(database *Database) [][]byte {
	res := [][]byte{}
	for i := 0; i < len(database.Entries); i++ {
		res = append(res, database.Entries[i].G_ri1)

	}
	return res
}

func (a *Auditor) ZKEncryption_RecordAndVerifyResponses(proving_client *Client,
	z1s [][]byte,
	z2s [][]byte,
	z3s [][]byte,
	X_primes [][]byte,
	Y_primes [][]byte,
	I1s [][]byte,
	I2s [][]byte,
	cs [][]byte) bool {
	// / reading the zkdatabase
	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false
	}
	var zkdatabase ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(zkdata, &zkdatabase)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false
	}

	// record the response
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z1s = z1s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z2s = z2s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Z3s = z3s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes = X_primes
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes = Y_primes
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I1s = I1s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I2s = I2s
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs = cs
	// fmt.Println(z1s)
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdatabase)
	// fmt.Println(updatedData)
	if err != nil {
		return false
	}

	// Write the updated data to the file
	err1 := os.WriteFile(a.ZKFileName, updatedData, 0644)
	if err1 != nil {
		return false
	}

	for i := 0; i < len(z1s); i++ {
		// first challenge
		X_z1, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_originals[i], z1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		H_z2, err := elgamal.ECDH_bytes(proving_client.H_shuffle, z2s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		first_challenge_left_hand, err := elgamal.Encrypt(X_z1, H_z2)
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		X_prime_c, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes[i], zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}
		first_challenge_right_hand, err := elgamal.Encrypt(X_prime_c, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		if !bytes.Equal(first_challenge_left_hand, first_challenge_right_hand) {
			fmt.Println("First challenge failed for client", proving_client.ID)
			return false
		}
		// else {
		// 	fmt.Println("First challenge PASSED for client", proving_client.ID)
		// }

		// second challenge
		Y_z1, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_originals[i], z1s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		H_z3, err := elgamal.ECDH_bytes(proving_client.H_shuffle, z3s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		second_challenge_left_hand, err := elgamal.Encrypt(Y_z1, H_z3)
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		Y_prime_c, err := elgamal.ECDH_bytes(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes[i], zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Cs[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}
		second_challenge_right_hand, err := elgamal.Encrypt(Y_prime_c, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.I2s[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false
		}

		if !bytes.Equal(second_challenge_left_hand, second_challenge_right_hand) {
			fmt.Println("Second challenge failed for client", proving_client.ID)
			return false
		}
		// else {
		// 	fmt.Println("Second challenge PASSED for client", proving_client.ID)
		// }

	}

	fmt.Println("ZK Proof for encryption is verified for client ", proving_client.ID)
	return true
}

func (a *Auditor) ZKDecryption_RecordAndVerifyResponses(
	rG_x [][]byte,
	rG_y [][]byte,
	Challenges [][]byte,
	S_x [][]byte,
	S_y [][]byte) (bool, error) {
	// / reading the zkdatabase
	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
	}

	var zkdatabase ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(zkdata, &zkdatabase)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
	}

	// read the database
	data, err := ReadDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}

	// record the response
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_X = rG_x
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_Y = rG_y
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Challenges = Challenges
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Ss_X = S_x
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Ss_Y = S_y

	// checks sG=rG+cH
	proving_client := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShufflerID
	pubkeys_client, err := LocatePublicKeyWithID(proving_client, database.Shuffle_PubKeys)

	if err != nil {
		log.Fatalf("%v", err)
		return false, err
	}

	// fmt.Println(S_x)

	for i := 0; i < len(S_x); i++ {
		// sG
		sG, err := elgamal.ECDH_bytes(pubkeys_client.G_i, S_x[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false, err
		}

		// rG
		rG := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.RG_X[i]

		// cH
		cH, err := elgamal.ECDH_bytes(pubkeys_client.H_i, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].DecryptionProof.Challenges[i])
		if err != nil {
			log.Fatalf("%v", err)
			return false, err
		}

		right_hand, err := elgamal.Encrypt(rG, cH)
		if err != nil {
			log.Fatalf("%v", err)
			return false, err
		}

		// sG=rG+cH
		if !bytes.Equal(sG, right_hand) {
			fmt.Println("Decryption Proof failed for client", proving_client)
			return false, nil
		}
	}

	// write back to the zkdatabase

	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdatabase)
	// fmt.Println(updatedData)
	if err != nil {
		return false, err
	}
	// Write the updated data to the file
	err = os.WriteFile(a.ZKFileName, updatedData, 0644)
	if err != nil {
		return false, err
	}

	return true, nil

}

// RSA_Q                                  *big.Int
// RSA_P                                  *big.Int
// RSA_subgroup_p_prime                   *big.Int
// RSA_subgroup_q_prime                   *big.Int
// RSA_subgroup_generators                []*big.Int

func (a *Auditor) ZKShuffling_RecordAndVerifyResponses(
	shuffled_entries [][][]byte,
	X_primes_encrypted_and_permutated [][]byte,
	Y_primes_encrypted_and_permutated [][]byte,
	commitments []*big.Int,
	Big_Vs [][]byte,
	V_prime_X []byte,
	V_prime_Y []byte,
	ChanllengesLambda [][]byte,
	RSA_Q *big.Int,
	RSA_P *big.Int,
	p_prime *big.Int,
	q_prime *big.Int,
	RSA_subgroup_generators []*big.Int,
	Updated_Shufflers_info []*ShuffleRecords,
	fs []*big.Int,
	small_z *big.Int,
	Z_ks [][]byte,
	Z_prime *big.Int) (bool, error) {
	// read zk database
	zkdata, err := ReadZKDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}
	var zkdatabase ZKDatabase

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(zkdata, &zkdatabase)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}

	// read the database
	data, err := ReadDatabase(a)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}
	var database Database

	// Unmarshal the byte slice into variable
	err = json.Unmarshal(data, &database)
	if err != nil {
		log.Fatalf("Error unmarshaling the JSON: %v", err)
		return false, err
	}

	// record the responses
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle = shuffled_entries
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.X_primes_encrypted_and_permutated_tagX = X_primes_encrypted_and_permutated
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Y_primes_encrypted_and_permutated_tagY = Y_primes_encrypted_and_permutated
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments = commitments
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Big_Vs = Big_Vs
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_X = V_prime_X
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_Y = V_prime_Y
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.ChanllengesLambda = ChanllengesLambda
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_Q = RSA_Q
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_P = RSA_P
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_p_prime = p_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_q_prime = q_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_generators = RSA_subgroup_generators
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info = Updated_Shufflers_info
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Fs = fs
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.SmallZ = small_z
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Z_prime = Z_prime
	zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Z_ks = Z_ks

	n := len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle)
	gs := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_subgroup_generators
	N := new(big.Int).Mul(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_P, zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.RSA_Q)
	// first check
	ts := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.ChanllengesLambda
	/// sum up fs and check if it is equal to sum of ts
	sum := big.NewInt(0)
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
		fmt.Println("First Test PASSED!!!!!!!!!Sum of fs is equal to sum of ts")
	} else {
		fmt.Println("Sum of fs is not equal to sum of ts")
		return false, nil
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
	second_condition_left_hand_side := new(big.Int).Set(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments[n])
	for i := 0; i < n; i++ {
		second_condition_left_hand_side = new(big.Int).Mul(second_condition_left_hand_side, new(big.Int).Exp(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Commitments[i], zklib.SetBigIntWithBytes(ts[i]), N))
	}
	second_condition_left_hand_side = new(big.Int).Mod(second_condition_left_hand_side, N)

	// fmt.Print("second_condition_left_hand_side ")
	// fmt.Println(second_condition_left_hand_side)
	// compare the two sides
	if second_condition_left_hand_side.Cmp(second_condition_right_hand_side) == 0 {
		fmt.Println("Second Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("they are not equal! Failed???????")
		return false, nil
	}

	// third check for the entries **** hardest part brutal
	// k means the index for individual pieces of the entry
	for k := 0; k < len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle[0]); k++ {
		third_check_left_hand_side := elgamal.ReturnInfinityPoint()
		for i := 0; i < n; i++ {
			C_i := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesAfterShuffle[i][k]
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

		third_check_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Big_Vs[k]
		for i := 0; i < n; i++ {
			c_i := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.EntriesBeforeShuffle[i][k]
			c_i_lambda_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(c_i, ts[i])
			if err != nil {
				panic(err)
			}
			third_check_right_hand_side, err = elgamal.Encrypt(third_check_right_hand_side, c_i_lambda_i)
		}
		// find the public key of the shuffler
		for i := 0; i < len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info); i++ {
			updated_shufflers := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Updated_Shufflers_info[i]
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
			return false, nil
		}
	}
	fmt.Println("Third Test concerning the cyphertext shuffling PASSED!!!!!!!!!")

	// fourth check for tag X
	fourth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.X_primes_encrypted_and_permutated_tagX[i], fs[i].Bytes())
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
	fourth_condition_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_X
	// find the public key of the shuffler
	shuffler_keys, err := LocatePublicKeyWithID(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShufflerID, database.Shuffle_PubKeys)
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
	tags_before_shuffle := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.X_primes
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
		fmt.Println("Fourth Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("Fourth Test FAILED????????")
		return false, nil
	}

	// fitfh check for tag Y
	fifth_condition_left_hand_side := elgamal.ReturnInfinityPoint()
	if err != nil {
		panic(err)
	}
	for i := 0; i < n; i++ {
		T_i_f_i, err := elgamal.ECDH_bytes_P256_arbitrary_scalar_len(zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.Y_primes_encrypted_and_permutated_tagY[i], fs[i].Bytes())
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
	fifth_condition_right_hand_side := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].ShuffleProof.V_prime_Y

	fifth_condition_right_hand_side, err = elgamal.Encrypt(fifth_condition_right_hand_side, encrypted_one_with_Z_prime)
	if err != nil {
		panic(err)
	}
	// lambdas := ts
	tags_before_shuffle_Y := zkdatabase.ZK_info[len(zkdatabase.ZK_info)-1].EncryptionProof.Y_primes
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
		fmt.Println("Fifth Test PASSED!!!!!!!!!")
	} else {
		fmt.Println("Fifth Test FAILED????????")
		return false, nil
	}

	//// write to the zk records
	// Marshal the updated array back to a byte slice
	updatedData, err := json.Marshal(zkdatabase)
	// fmt.Println(updatedData)
	if err != nil {
		return false, err
	}
	// Write the updated data to the file
	err = os.WriteFile(a.ZKFileName, updatedData, 0644)

	if err != nil {
		return false, err
	}

	return true, nil

}

func LocatePublicKeyWithID(clientID int, ShufflerPublicKeys []*ShufflePubKeys) (*ShufflePubKeys, error) {
	for i := 0; i < len(ShufflerPublicKeys); i++ {
		if clientID == ShufflerPublicKeys[i].ID {
			return ShufflerPublicKeys[i], nil
		}
	}
	return nil, errors.New("Shuffler Public Key Not Found")
}
