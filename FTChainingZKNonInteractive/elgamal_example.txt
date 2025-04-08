example elgamal
    
    curve := ecdh.P256()

	/// auditer action
	// Generate key for the auditer
	priv1, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	/// client will only use auditer's public key
	pub1 := priv1.PublicKey()
	// c1 := pub1.Bytes()

	//client action
	// Generate key for one client
	priv2, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	///generate a message, this represent a web certificate
	// report_msg := elgamal.Generate_one_bytes()
	report_msg := elgamal.Generate_msg_bytes()
	/// obtain the shared secrete
	shared_key_cli, err := priv2.ECDH(pub1)
	if err != nil {
		panic(err)
	}

	//// generate a cypher text, c2
	cyphertext, err := elgamal.Encrypt(shared_key_cli, report_msg)
	if err != nil {
		panic(err)
	}
	/// pub2 is client c1
	pub2 := priv2.PublicKey()
	/////client action end, the auditor gets the cyphertext and c1

	shared_key1, err := priv1.ECDH(pub2)
	if err != nil {
		panic(err)
	}
	plaintext, err := elgamal.Decrypt(shared_key1, cyphertext)

	for _, b := range cyphertext {
		fmt.Printf("%x ", b)
	}

	// fmt.Println()
	// for _, b := range report_msg {
	// 	fmt.Printf("%x ", b)
	// }

	// fmt.Println()
	// for _, b := range plaintext {
	// 	fmt.Printf("%x ", b)
	// }
	fmt.Println()
	if string(report_msg) == string(plaintext) {
		fmt.Println("Decryption successful!")
	} else {
		fmt.Println("Decryption failed!")
	}