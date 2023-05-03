package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	RootKey  []byte
	UserUUID uuid.UUID

	// private keys
	SecretKey userlib.PKEDecKey
	SignKey   userlib.DSSignKey

	// public keys
	PublicKey userlib.PKEEncKey
	VerifyKey userlib.DSVerifyKey

	//rsa map key and sign map key
	Rsa_map  string
	Sign_map string
	// file dictionary store where the files are
	File_meta_dict  map[string]uuid.UUID
	Share_meta_dict map[string]uuid.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type MetaData struct {
	File_uuid         uuid.UUID
	Owner_node        *Node
	File_enc_key      []byte
	File_hmac_key     []byte
	Share_enc_key     []byte
	Share_hmac_key    []byte
	Slice_size        []int
	Iv                []byte
	InvitationPackptr uuid.UUID
	Shared            bool
	Mynode            *Node
}

type Node struct {
	Username string
	Invite   uuid.UUID
	Children []*Node
}

type Invitation struct {
	Share_Meta_uuid     uuid.UUID
	Share_Meta_enc_key  []byte
	Share_Meta_hmac_key []byte
}

type Invitation_Package struct {
	RSA_inv_enc_key  []byte
	RSA_inv_hmac_key []byte
	Enc_invitation   []byte
	Sendernode       *Node
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// first we need to check that the username should not be empty
	if username == "" {
		return nil, errors.New("Username is Empty")
	}
	// we do not have any requirement for password so we can build a user now
	var userdata User
	// get a byte version for later operations
	userdata.Username = username
	userdata.Password = password
	username_b := []byte(username)
	password_b := []byte(password)
	// Encrypt Username Hash(username||uuid||'user')
	// want out UUID to be from hashed_username
	username_to_hash := append(username_b, []byte("uuid")...)
	hashed_username := userlib.Hash(username_to_hash)[:16]
	user_uuid, err := uuid.FromBytes(hashed_username)
	userdata.UserUUID = user_uuid

	// UUID comes from different username, so if UUID is not the same, which means new username
	_, existed := userlib.DatastoreGet(user_uuid)
	if existed {
		return nil, errors.New("Already existed, username:" + string(username))
	}

	// now we already verify that the user do not exist and we can set up
	// Generate the Root key now
	RootKey := userlib.Argon2Key(password_b, username_b, 16)
	userdata.RootKey = RootKey
	// use the root key to generate different for encrption and HMAC
	// we need to change it into 16 bytes so that they can be used in the function
	enc_key, err := userlib.HashKDF(RootKey, []byte("Enc"))
	hmac_key, err := userlib.HashKDF(RootKey, []byte("Hmac"))
	useable_enc_key := enc_key[:16]
	useable_hmac_key := hmac_key[:16]

	// generate the public key that is used in future file sharing
	// store all of them in the key_store, those who know our username can get the public key
	user_rsa_key := fmt.Sprintf("%s_RSA", username)
	user_sign_key := fmt.Sprintf("%s_SIGN", username)

	// if the data store has been attacked, we have another check for the existence
	_, has_user := userlib.KeystoreGet(user_rsa_key)
	if has_user {
		return nil, errors.New("User already existed for" + string(username))
	}
	// initialize the map
	userdata.File_meta_dict = make(map[string]uuid.UUID)
	userdata.Share_meta_dict = make(map[string]uuid.UUID)

	// Generate the key pair, save the private key and store the public key in the key store
	userdata.PublicKey, userdata.SecretKey, err = userlib.PKEKeyGen()
	err = userlib.KeystoreSet(string(user_rsa_key), userdata.PublicKey)
	userdata.Rsa_map = string(user_rsa_key)

	userdata.SignKey, userdata.VerifyKey, err = userlib.DSKeyGen()
	err = userlib.KeystoreSet(string(user_sign_key), userdata.VerifyKey)
	userdata.Sign_map = string(user_sign_key)

	// package the whole structure and ensure confidentiality and intergrity
	bytes, _ := json.Marshal(userdata)
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_bytes, err := Enc_Mac(bytes, useable_enc_key, useable_hmac_key, iv)
	userlib.DatastoreSet(user_uuid, enc_mac_bytes)
	return &userdata, nil
}

func reload_invitation(secretkey userlib.PKEDecKey, filename string, packPtr uuid.UUID, metadata MetaData, userdata *User) (updated_metadata MetaData, upd_userdata *User, err error) {
	var pack Invitation_Package
	var invitation Invitation
	var share_metadata MetaData

	//userlib.DebugMsg("User %s's UUID: %s", userdata.Username, packPtr)
	pack_byte, _ := userlib.DatastoreGet(packPtr)
	err = json.Unmarshal(pack_byte, &pack)
	if err != nil {
		return share_metadata, userdata, err
	}
	parent_name := pack.Sendernode.Username
	//userlib.DebugMsg("parent name : %s", parent_name)
	// verify the invitation is comes from the sender
	user_sign_key := fmt.Sprintf("%s_SIGN", parent_name)
	verify_key, exist := userlib.KeystoreGet(user_sign_key)
	if !exist {
		return share_metadata, userdata, errors.New("load_invitation can not find public key")
	}
	enc_cipher := pack.RSA_inv_enc_key[256:]
	enc_sign := pack.RSA_inv_enc_key[:256]
	hmac_cipher := pack.RSA_inv_hmac_key[256:]
	hmac_sign := pack.RSA_inv_hmac_key[:256]

	enc_err := userlib.DSVerify(verify_key, enc_cipher, enc_sign)
	hmac_err := userlib.DSVerify(verify_key, hmac_cipher, hmac_sign)
	if enc_err != nil || hmac_err != nil {
		return share_metadata, userdata, errors.New("the message has been changed")
	}

	//userlib.DebugMsg("len1: %d, len2: %s", enc_cipher, hmac_cipher)
	//userlib.DebugMsg("keylen1: %d", secretkey)
	//userlib.DebugMsg("Accepted cipher text: %v", enc_cipher)
	enc_key, err1 := userlib.PKEDec(userdata.SecretKey, enc_cipher)
	hmac_key, err2 := userlib.PKEDec(userdata.SecretKey, hmac_cipher)
	//userlib.DebugMsg("err1: %s, err2: %s", err1, err2)
	if err1 != nil || err2 != nil {
		return share_metadata, userdata, errors.New("You have been kicked out, sorry")
	}

	cipher_Inv := pack.Enc_invitation
	invitation_bytes, err := decrypt(cipher_Inv, enc_key[:16], hmac_key[:16])

	_ = json.Unmarshal(invitation_bytes, &invitation)

	//userlib.DebugMsg("Updated, The UUID get by the user: %s", invitation.Share_Meta_uuid)

	new_share_meta_UUID := invitation.Share_Meta_uuid
	new_share_meta_enc_key := invitation.Share_Meta_enc_key
	new_share_meta_hmac_key := invitation.Share_Meta_hmac_key
	userdata.Share_meta_dict[filename] = new_share_meta_UUID

	metadata.Share_enc_key = new_share_meta_enc_key[:16]
	metadata.Share_hmac_key = new_share_meta_hmac_key[:16]

	share_ciphertext, _ := userlib.DatastoreGet(new_share_meta_UUID)
	decrypted_share, err := decrypt(share_ciphertext, metadata.Share_enc_key, metadata.Share_hmac_key)
	if err != nil {
		return share_metadata, userdata, err
	}
	_ = json.Unmarshal(decrypted_share, &share_metadata)

	metadata.File_uuid = share_metadata.File_uuid
	metadata.File_enc_key = share_metadata.File_enc_key
	metadata.File_hmac_key = share_metadata.File_hmac_key
	metadata.Owner_node = share_metadata.Owner_node

	return metadata, userdata, nil

}

func Enc_Mac(data, enc_key, hmac_key, iv []byte) (result []byte, err error) {

	data_encrypted := userlib.SymEnc(enc_key, iv, data)
	data_mac, err := userlib.HMACEval(hmac_key, data_encrypted)
	if err != nil {
		return nil, err
	}
	// data looks like : MAC || encrypted_data
	data_encrypted_mac := append(data_mac, data_encrypted...) // 64 length for signature

	return data_encrypted_mac, nil
}
func append_demac_mac(ciphertext, enc_key, hmac_key, content, iv []byte) (result []byte, err error, l int) {
	encrypted_data := ciphertext[64:]
	Hmac_1, err := userlib.HMACEval(hmac_key, encrypted_data)
	Hmac_2 := ciphertext[0:64]
	equal := userlib.HMACEqual(Hmac_1, Hmac_2)
	// if mac do not match, some changes happen or the password is not correct.
	if !equal {
		return nil, errors.New("Attackers did something! Stop decryption!"), 0
	}
	// safe now, we need to encrypt content and combine them then hmac
	content_encrypted := userlib.SymEnc(enc_key, iv, content)
	l = len(content_encrypted)
	total_ciphertext := append(encrypted_data, content_encrypted...)
	new_Hmac, err := userlib.HMACEval(hmac_key, total_ciphertext)
	final_res := append(new_Hmac, total_ciphertext...)
	return final_res, nil, l
}

func decrypt(ciphertext, enc_key, hmac_key []byte) (result []byte, err error) {
	if len(ciphertext) < 64 {
		return nil, errors.New("decrypt")
	}
	encrypted_data := ciphertext[64:]

	Hmac_1, err := userlib.HMACEval(hmac_key, encrypted_data)
	Hmac_2 := ciphertext[0:64]
	equal := userlib.HMACEqual(Hmac_1, Hmac_2)
	// if mac do not match, some changes happen or the password is not correct.
	if !equal {
		return nil, errors.New("Attackers did something! Stop decryption!")
	}
	// nobody change the message, so it seems we can decrypt the message
	decrypted_data := userlib.SymDec(enc_key, encrypted_data)
	return decrypted_data, nil
}

func file_decrypt(ciphertext, enc_key, hmac_key []byte, slice_size []int) (result []byte, err error) {
	//first still check the hmac first
	if len(ciphertext) < 64 {
		return nil, errors.New("filedec")
	}
	encrypted_content := ciphertext[64:]
	Hmac_1, err := userlib.HMACEval(hmac_key, encrypted_content)
	Hmac_2 := ciphertext[0:64]
	equal := userlib.HMACEqual(Hmac_1, Hmac_2)
	// if mac do not match, some changes happen or the password is not correct.
	if !equal {
		return nil, errors.New("Attackers did something! Stop decryption!")
	}
	// nobody change the message, so it seems we can decrypt the message
	// slice by slice and combine them together
	sum := 0
	content := make([]byte, 0)
	for i := 0; i < len(slice_size); i++ {
		if (slice_size[i]) == 0 && i == 0 {
			return nil, errors.New("slice sb problem,i = 0")
		}
		slice_enc_data := encrypted_content[sum : sum+slice_size[i]]
		decrypted_content := userlib.SymDec(enc_key, slice_enc_data)
		sum += slice_size[i]
		content = append(content, decrypted_content...)
	}
	return content, nil
}
func TreeAddChild(tree *Node, child *Node, parent string) (new_tree, parent_node *Node, err error) {
	var bfs_queue []*Node
	bfs_queue = append(bfs_queue, tree)
	for len(bfs_queue) > 0 {
		node := bfs_queue[0]
		if node.Username == parent {
			node.Children = append(node.Children, child)
			return tree, node, nil

		}
		for i := 0; i < len(node.Children); i++ {
			bfs_queue = append(bfs_queue, node.Children[i])
		}
		bfs_queue = bfs_queue[1:]
	}
	return tree, nil, nil
}

func Reinvite(owner *Node, inv_enc_key, inv_hmac_key, enc_Invitation []byte, signkey userlib.DSSignKey) (new_tree *Node, err error) {
	var bfs_queue []*Node
	var childrens []*Node
	bfs_queue = append(bfs_queue, owner)
	for len(bfs_queue) > 0 {
		node := bfs_queue[0]
		for i := 0; i < len(node.Children); i++ {
			var new_pack Invitation_Package
			new_pack.Sendernode = owner
			new_pack.Enc_invitation = enc_Invitation
			child_rsa_key := fmt.Sprintf("%s_RSA", node.Children[i].Username)
			rsa_key, rechas_user := userlib.KeystoreGet(child_rsa_key)
			if !rechas_user {
				return owner, errors.New("Reinvite")
			}
			R_enc_key, _ := userlib.PKEEnc(rsa_key, inv_enc_key)
			R_hmac_key, _ := userlib.PKEEnc(rsa_key, inv_hmac_key)

			new_pack.RSA_inv_enc_key = R_enc_key
			new_pack.RSA_inv_hmac_key = R_hmac_key

			sign_enc, err1 := userlib.DSSign(signkey, new_pack.RSA_inv_enc_key)
			sign_hmac, err2 := userlib.DSSign(signkey, new_pack.RSA_inv_hmac_key)
			if err1 != nil || err2 != nil {
				return owner, errors.New("Reinvite sign issue")
			}
			new_pack.RSA_inv_enc_key = append(sign_enc, new_pack.RSA_inv_enc_key...)
			new_pack.RSA_inv_hmac_key = append(sign_hmac, new_pack.RSA_inv_hmac_key...)
			new_pack_bytes, _ := json.Marshal(new_pack)
			userlib.DatastoreSet(node.Children[i].Invite, new_pack_bytes)
			//userlib.DebugMsg("children%d is %s", i, node.Children[i].Username)
			bfs_queue = append(bfs_queue, node.Children[i])
			childrens = append(childrens, node.Children[i])
		}
		bfs_queue = bfs_queue[1:]
	}

	owner.Children = childrens
	for i := 0; i < len(owner.Children); i++ {
		owner.Children[i].Children = nil
	}
	return owner, nil
}

func ChildLocation(children []*Node, tag string) int {
	for i := 0; i < len(children); i++ {
		if children[i].Username == tag {
			return i
		}
	}
	return -1
}
func RemoveDirectChild(tree *Node, target_username string) (new_tree *Node, err error) {
	loc := ChildLocation(tree.Children, target_username)
	if loc == -1 {
		return nil, errors.New("Username not in the tree or Username is not a direct child")
	}
	tree.Children[loc] = tree.Children[len(tree.Children)-1]
	tree.Children = tree.Children[:len(tree.Children)-1]
	return tree, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// first we need to check that the username should not be empty
	if username == "" {
		return nil, errors.New("Username is Empty")
	}
	// almost the same thing as the inituser just to make sure that the UUID is existed
	username_b := []byte(username)
	password_b := []byte(password)
	username_to_hash := append(username_b, []byte("uuid")...)
	hashed_username := userlib.Hash(username_to_hash)[:16]
	user_uuid, err := uuid.FromBytes(hashed_username)
	ciphertext, existed := userlib.DatastoreGet(user_uuid)
	if !existed {
		return nil, errors.New("The username is new, set up first")
	}
	// now it seems the username is existed, what about the password?
	// To verify the password, we just need to verify the rootkey
	RootKey := userlib.Argon2Key(password_b, username_b, 16)
	// generate the "keys" by the "root key"
	// if the root key is wrong, the enc_key and hmac_key can not be right
	enc_key, err := userlib.HashKDF(RootKey, []byte("Enc"))
	hmac_key, err := userlib.HashKDF(RootKey, []byte("Hmac"))
	useable_enc_key := enc_key[:16]
	useable_hmac_key := hmac_key[:16]

	decrypted_data, err := decrypt(ciphertext, useable_enc_key, useable_hmac_key)
	if err != nil {
		return nil, err
	}
	// username and password is right, and the mac is matched
	// get the marshalled data & unmarshall it
	var userdata User
	userdataptr = &userdata
	json_err := json.Unmarshal(decrypted_data, userdataptr)
	if json_err != nil {
		return nil, errors.New("seems something wrong about the json")
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// currently it's a pretty simple version
	// check whether the user is valid from keystore and datastore
	// what can we have for the given userdata?
	_, has_user := userlib.KeystoreGet(userdata.Rsa_map)
	_, has_user_2 := userlib.DatastoreGet(userdata.UserUUID)

	if !has_user_2 || !has_user {
		return errors.New("Current user does not exist or attackers, storefile")
	}
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	// we need to store the new metadata for later share

	var metadata MetaData
	var share_metadata MetaData
	Rootkey := userdata.RootKey
	username_b := []byte(userdata.Username)
	password_b := []byte(userdata.Password)
	// want out UUID to be from hashed_username, generate it for the new file
	//username || file_uuid
	//username || file_meta_uuid
	// generating UUID if not existed
	file_to_hash := append(username_b, []byte("file_uuid")...)
	file_meta_to_hash := append(username_b, []byte("file_meta_uuid")...)
	share_meta_to_hash := append(username_b, []byte("share_meta_uuid")...)
	hashed_file_uuid := userlib.Hash(file_to_hash)
	hashed_meta_uuid := userlib.Hash(file_meta_to_hash)
	hashed_share_meta_uuid := userlib.Hash(share_meta_to_hash)
	// hashed || filename
	file_uuid_1 := append(hashed_file_uuid, []byte(filename)...)
	meta_uuid_1 := append(hashed_meta_uuid, []byte(filename)...)
	share_meta_uuid_1 := append(hashed_share_meta_uuid, []byte(filename)...)
	// hash again for the UUID
	file_uuid_2 := userlib.Hash(file_uuid_1)[:16]
	meta_uuid_2 := userlib.Hash(meta_uuid_1)[:16]
	share_meta_uuid_2 := userlib.Hash(share_meta_uuid_1)[:16]
	// check whether this file already existed or not, get the uuid if existed
	meta_uuid, file_meta_existed := userdata.File_meta_dict[filename]
	share_meta_uuid, share_meta_existed := userdata.Share_meta_dict[filename]

	_, meta_existed := userlib.DatastoreGet(meta_uuid)
	if meta_existed && !share_meta_existed {
		return errors.New("Somewhere we do not store the share_meta_UUID")
	}

	// we can get the meta_key and content_key
	meta_key := userlib.Argon2Key(Rootkey, meta_uuid_1, 16)
	content_key := userlib.Argon2Key(Rootkey, file_uuid_1, 16)
	share_meta_key := userlib.Argon2Key(Rootkey, share_meta_uuid_1, 16)
	//then we get the useable one from the 2 keys
	meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
	meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))
	use_meta_enc_key := meta_enc_key[:16]
	use_meta_hmac_key := meta_hmac_key[:16]

	content_enc_key, err := userlib.HashKDF(content_key, []byte("Enc"))
	content_hmac_key, err := userlib.HashKDF(content_key, []byte("Hmac"))
	use_content_enc_key := content_enc_key[:16]
	use_content_hmac_key := content_hmac_key[:16]

	share_meta_enc_key, err := userlib.HashKDF(share_meta_key, []byte("Enc"))
	share_meta_hmac_key, err := userlib.HashKDF(share_meta_key, []byte("Hmac"))
	use_share_meta_enc_key := share_meta_enc_key[:16]
	use_share_meta_hmac_key := share_meta_hmac_key[:16]

	// the datastore is not secure, which means the attacker may change or delete
	// some dangerous situations
	if file_meta_existed && !meta_existed {
		return errors.New("Attckers did some bad things to stored metadata")
	}

	// seems all right, at least there are something and we must verify the content if attackers did something
	if file_meta_existed && meta_existed {
		// we just need to overwrite it!
		// for metadata, the key is always the same, by generating
		// get metadata first
		ciphertext, _ := userlib.DatastoreGet(meta_uuid)
		decrypted_meta, err := decrypt(ciphertext, use_meta_enc_key, use_meta_hmac_key)
		if err != nil {
			return errors.New("Attackers did something! Stop decryption!")
		}
		json_err := json.Unmarshal(decrypted_meta, &metadata)
		if json_err != nil {
			return errors.New("seems something wrong about the json")
		}

		// reloading process!!!
		if metadata.Shared {
			metadata, userdata, err = reload_invitation(userdata.SecretKey, filename, metadata.InvitationPackptr, metadata, userdata)
			// we reload the share metadata information, so we need to update the information
		}
		if err != nil {
			return err
		}

		//now we successfully get the struct, we can find everything we need!
		use_content_enc_key = metadata.File_enc_key[:16]
		use_content_hmac_key = metadata.File_hmac_key[:16]
		use_share_meta_enc_key = metadata.Share_enc_key[:16]
		use_share_meta_hmac_key = metadata.Share_hmac_key[:16]
		file_uuid := metadata.File_uuid
		iv := metadata.Iv

		// then we re-encrypt the file and store it
		enc_mac_content, err := Enc_Mac(content, use_content_enc_key, use_content_hmac_key, iv)
		if err != nil {
			return errors.New("something weird happens")
		}
		userlib.DatastoreSet(file_uuid, enc_mac_content)

		// we should update the slice because we overwrite it
		// the length comes from (whole length - hmac)
		var slice []int
		slice = append(slice, len(enc_mac_content)-64)
		metadata.Slice_size = slice
		metadata.Owner_node = share_metadata.Owner_node
		// then we gonna store the file and the file's meta_data
		iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
		share_metadata = metadata

	}
	// best one, it is empty so we just add a new one
	if !file_meta_existed {
		//translate byte to UUID
		file_uuid, err := uuid.FromBytes(file_uuid_2)
		if err != nil {
			return err
		}
		meta_uuid, err = uuid.FromBytes(meta_uuid_2)
		if err != nil {
			return err
		}
		share_meta_uuid, err = uuid.FromBytes(share_meta_uuid_2)
		if err != nil {
			return err
		}
		userdata.File_meta_dict[filename] = meta_uuid
		userdata.Share_meta_dict[filename] = share_meta_uuid

		// generate the content key for encrypting the content
		iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		enc_mac_content, err := Enc_Mac(content, use_content_enc_key, use_content_hmac_key, iv)

		// generate another IV to be used in file encryption
		iv_file := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		// store the keys into the metadata and UUID
		metadata.File_uuid = file_uuid
		metadata.File_enc_key = use_content_enc_key
		metadata.File_hmac_key = use_content_hmac_key
		metadata.Share_enc_key = share_meta_enc_key[:16]
		metadata.Share_hmac_key = share_meta_hmac_key[:16]
		var slice []int
		var Mynode Node
		slice = append(slice, len(enc_mac_content)-64)
		metadata.Slice_size = slice
		metadata.Iv = iv_file
		Mynode.Username = userdata.Username
		metadata.Owner_node = &Mynode
		metadata.Mynode = &Mynode
		metadata.Shared = false

		// check if there is something weird(though it should be impossible)
		// do we need to consider it ?
		_, not_empty := userlib.DatastoreGet(file_uuid)
		if not_empty {
			return errors.New("not good, the attacker add something to the file UUID")
		}
		_, not_empty_1 := userlib.DatastoreGet(meta_uuid)
		if not_empty_1 {
			return errors.New("not good, the attacker add something to the meta UUID")
		}
		_, not_empty_2 := userlib.DatastoreGet(share_meta_uuid)
		if not_empty_2 {
			return errors.New("not good, the attacker add something to the share UUID")
		}
		userlib.DatastoreSet(file_uuid, enc_mac_content)

		// we need to store the share_metadata for sharing later
		share_metadata = metadata

	}
	// store the whole struct back to the data store

	username_to_hash := append(username_b, []byte("uuid")...)
	hashed_username := userlib.Hash(username_to_hash)[:16]
	user_uuid, err := uuid.FromBytes(hashed_username)
	RootKey := userlib.Argon2Key(password_b, username_b, 16)
	enc_key, err := userlib.HashKDF(RootKey, []byte("Enc"))
	hmac_key, err := userlib.HashKDF(RootKey, []byte("Hmac"))
	useable_enc_key := enc_key[:16]
	useable_hmac_key := hmac_key[:16]

	// store it into the map
	share_metadata.Share_enc_key = []byte{}
	share_metadata.Share_hmac_key = []byte{}

	bytes, _ := json.Marshal(userdata)
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_bytes, err := Enc_Mac(bytes, useable_enc_key, useable_hmac_key, iv)
	userlib.DatastoreSet(user_uuid, enc_mac_bytes)

	// store the metadata

	meta_bytes, _ := json.Marshal(metadata)
	enc_mac_meta, err := Enc_Mac(meta_bytes, use_meta_enc_key, use_meta_hmac_key, metadata.Iv)
	userlib.DatastoreSet(userdata.File_meta_dict[filename], enc_mac_meta)

	// store the share_metadata
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	share_meta_bytes, _ := json.Marshal(share_metadata)
	enc_mac_share_meta, err := Enc_Mac(share_meta_bytes, use_share_meta_enc_key, use_share_meta_hmac_key, iv)
	userlib.DatastoreSet(userdata.Share_meta_dict[filename], enc_mac_share_meta)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// check the validity of the user first
	_, has_user := userlib.KeystoreGet(userdata.Rsa_map)
	_, has_user_2 := userlib.DatastoreGet(userdata.UserUUID)
	if !has_user_2 || !has_user {
		return errors.New("Current user does not exist or attackers,append")
	}
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	// check whether this file already existed or not, get the uuid if existed
	meta_uuid, file_meta_existed := userdata.File_meta_dict[filename]

	meta_ciphertext, meta_existed := userlib.DatastoreGet(meta_uuid)
	// improper call, append must be called after existence
	if !file_meta_existed || !meta_existed {
		return errors.New("Not a valid operation, you really mean append?")
	}

	var metadata MetaData
	var share_metadata MetaData

	username_b := []byte(userdata.Username)
	file_meta_to_hash := append(username_b, []byte("file_meta_uuid")...)
	hashed_meta_uuid := userlib.Hash(file_meta_to_hash)
	meta_uuid_1 := append(hashed_meta_uuid, []byte(filename)...)

	Rootkey := userdata.RootKey
	// get the meta keys to verify everything is well
	meta_key := userlib.Argon2Key(Rootkey, meta_uuid_1, 16)
	meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
	meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))
	use_meta_enc_key := meta_enc_key[:16]
	use_meta_hmac_key := meta_hmac_key[:16]

	decrypted_meta, err := decrypt(meta_ciphertext, use_meta_enc_key, use_meta_hmac_key)
	if err != nil {
		return errors.New("Attackers did something! Stop decryption!")
	}

	json_err := json.Unmarshal(decrypted_meta, &metadata)
	if json_err != nil {
		return errors.New("seems something wrong about the json")
	}

	// reloading process!!!
	if metadata.Shared {
		metadata, userdata, err = reload_invitation(userdata.SecretKey, filename, metadata.InvitationPackptr, metadata, userdata)
	}
	if err != nil {
		return err
	}

	//now we successfully get the struct, we can find everything we need!
	// we only encrypt it and concatenate it with the origin one
	// every time when we add something, remac it again
	file_uuid := metadata.File_uuid
	share_meta_uuid, ext := userdata.Share_meta_dict[filename]
	if !ext {
		return errors.New("share meta_uuid not exist")
	}

	content_enc_key := metadata.File_enc_key
	content_hmac_key := metadata.File_hmac_key
	iv := metadata.Iv
	//userlib.DebugMsg("the key: %s", metadata.Share_enc_key)

	share_enc_key := metadata.Share_enc_key
	share_hmac_key := metadata.Share_hmac_key
	use_share_meta_enc_key := share_enc_key[:16]
	use_share_meta_hmac_key := share_hmac_key[:16]

	share_ciphertext, share_exist := userlib.DatastoreGet(share_meta_uuid)
	if !share_exist {
		return errors.New("unable to get the share metadata")
	}
	decrypted_share, err := decrypt(share_ciphertext, use_share_meta_enc_key, use_share_meta_hmac_key)
	if err != nil {
		return err
	}

	json_err = json.Unmarshal(decrypted_share, &share_metadata)
	if json_err != nil {
		return errors.New("seems something wrong about the json")
	}

	metadata.Slice_size = share_metadata.Slice_size
	metadata.Owner_node = share_metadata.Owner_node
	// check if there is something in the file before
	file_ciphertext_before, existed := userlib.DatastoreGet(file_uuid)
	if !existed {
		return errors.New("there is no file before")
	}

	appended_content, err, length := append_demac_mac(file_ciphertext_before, content_enc_key, content_hmac_key, content, iv)
	if err != nil {
		return err
	}
	// update the slice_size
	metadata.Slice_size = append(metadata.Slice_size, length)
	// we gonna copy a share_meta and store it
	share_metadata = metadata

	share_metadata.Share_enc_key = []byte{}
	share_metadata.Share_hmac_key = []byte{}
	// then we gonna store the file and the file's meta_data
	meta_bytes, _ := json.Marshal(metadata)
	share_meta_bytes, _ := json.Marshal(share_metadata)
	// same, do not need to keep iv
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_meta, err := Enc_Mac(meta_bytes, use_meta_enc_key, use_meta_hmac_key, iv)
	enc_mac_share_meta, err := Enc_Mac(share_meta_bytes, use_share_meta_enc_key, use_share_meta_hmac_key, iv)
	userlib.DatastoreSet(file_uuid, appended_content)
	userlib.DatastoreSet(meta_uuid, enc_mac_meta)
	userlib.DatastoreSet(share_meta_uuid, enc_mac_share_meta)

	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// check the validity of the user first
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	// check whether this file already existed or not, get the uuid if existed
	meta_uuid, file_meta_existed := userdata.File_meta_dict[filename]
	_, meta_existed := userlib.DatastoreGet(meta_uuid)
	// improper call, append must be called after existence
	if !file_meta_existed || !meta_existed {
		return nil, errors.New("Not a valid operation, nothing to load")
	}
	file_meta_uuid := meta_uuid
	var metadata MetaData
	var share_metadata MetaData
	username_b := []byte(userdata.Username)
	file_meta_to_hash := append(username_b, []byte("file_meta_uuid")...)
	hashed_meta_uuid := userlib.Hash(file_meta_to_hash)
	meta_uuid_1 := append(hashed_meta_uuid, []byte(filename)...)

	Rootkey := userdata.RootKey
	// get the meta keys to verify everything is well
	meta_key := userlib.Argon2Key(Rootkey, meta_uuid_1, 16)
	meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
	meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))
	use_meta_enc_key := meta_enc_key[:16]
	use_meta_hmac_key := meta_hmac_key[:16]
	if err != nil {
		return nil, err
	}
	ciphertext, _ := userlib.DatastoreGet(file_meta_uuid)

	decrypted_meta, err := decrypt(ciphertext, use_meta_enc_key, use_meta_hmac_key)
	if err != nil {
		return nil, err
	}

	json_err := json.Unmarshal(decrypted_meta, &metadata)
	if json_err != nil {
		return nil, errors.New("seems something wrong about the json")
	}
	//now we successfully get the struct, we can find everything we need!
	if metadata.Shared {
		//userlib.DebugMsg("loading new inv")
		metadata, userdata, err = reload_invitation(userdata.SecretKey, filename, metadata.InvitationPackptr, metadata, userdata)
		// we reload the share metadata information, so we need to update the information
		if err != nil {
			return nil, err
		}
	}

	content_enc_key := metadata.File_enc_key
	content_hmac_key := metadata.File_hmac_key
	file_uuid := metadata.File_uuid
	share_meta_enc_key := metadata.Share_enc_key
	share_meta_hmac_key := metadata.Share_hmac_key
	// nothing to store
	share_ciphertext, something := userlib.DatastoreGet(userdata.Share_meta_dict[filename])
	//userlib.DebugMsg("the cipher : %s", share_ciphertext)
	if !something {
		return nil, errors.New("Nothing here now")
	}
	//userlib.DebugMsg(string(share_ciphertext))

	//userlib.DebugMsg("length of cipher : %d", len(share_ciphertext))
	decrypted_share_meta, err := decrypt(share_ciphertext, share_meta_enc_key[:16], share_meta_hmac_key[:16])
	if err != nil {
		return nil, err
	}

	jsonerr1 := json.Unmarshal(decrypted_share_meta, &share_metadata)
	if jsonerr1 != nil {
		return nil, errors.New("seems something wrong about the json")
	}

	metadata.Slice_size = share_metadata.Slice_size
	metadata.Owner_node = share_metadata.Owner_node
	meta_bytes, err := json.Marshal(metadata)

	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_meta, err := Enc_Mac(meta_bytes, meta_enc_key[:16], meta_hmac_key[:16], iv)
	userlib.DatastoreSet(meta_uuid, enc_mac_meta)

	ciphertext_file, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return nil, errors.New("attackers delete the data! Run!")
	}
	content_byte, err := file_decrypt(ciphertext_file, content_enc_key[:16], content_hmac_key[:16], metadata.Slice_size)
	if err != nil {
		return nil, err
	}
	return content_byte, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// create a nil uuid
	nil_UUID, _ := uuid.FromBytes(userlib.Hash([]byte("Nil"))[:16])
	//see whether user exists
	// problem
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil_UUID, err
	}
	//see whether recipient exists
	username_a := []byte(recipientUsername)
	username_to_hash := append(username_a, []byte("uuid")...)
	hashed_username := userlib.Hash(username_to_hash)[:16]
	recuser_uuid, err := uuid.FromBytes(hashed_username)
	recuser_rsa_key := fmt.Sprintf("%s_RSA", recipientUsername)
	rsa_key, rechas_user := userlib.KeystoreGet(string(recuser_rsa_key))
	_, rechas_user_2 := userlib.DatastoreGet(recuser_uuid)
	if !rechas_user || !rechas_user_2 {
		return nil_UUID, errors.New("recipient does not exist or attackerssss")
	}
	//see whether file and meta data exist
	meta_uuid, file_dict_existed := userdata.File_meta_dict[filename]

	meta_file, data_existed := userlib.DatastoreGet(meta_uuid)

	if !file_dict_existed || !data_existed {
		return nil_UUID, errors.New("file does not exist")
	}

	username_b := []byte(userdata.Username)
	file_meta_to_hash := append(username_b, []byte("file_meta_uuid")...)
	hashed_meta_uuid := userlib.Hash(file_meta_to_hash)
	meta_uuid_1 := append(hashed_meta_uuid, []byte(filename)...)
	// want to store it in the datastore, we need to deal with the content
	Rootkey := userdata.RootKey

	// enc and hmac meta data struct

	meta_key := userlib.Argon2Key(Rootkey, meta_uuid_1, 16)
	meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
	meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))

	meta, err := decrypt(meta_file, meta_enc_key[:16], meta_hmac_key[:16])
	if err != nil {
		return nil_UUID, errors.New("metafile does not exist")
	}
	var metadata MetaData
	var share_metadata MetaData
	json_err := json.Unmarshal(meta, &metadata)
	if json_err != nil {
		return nil_UUID, errors.New("seems something wrong about the json")
	}

	// reloading process!!!
	if metadata.Shared {
		metadata, userdata, err = reload_invitation(userdata.SecretKey, filename, metadata.InvitationPackptr, metadata, userdata)
		// we reload the share metadata information, so we need to update the information
		if err != nil {
			return nil_UUID, err
		}
	}

	file_enc_key := metadata.File_enc_key[:16]
	file_hmac_key := metadata.File_hmac_key[:16]
	file_uuid := metadata.File_uuid
	file, file_exist := userlib.DatastoreGet(file_uuid)
	_, err = decrypt(file, file_enc_key, file_hmac_key)
	if !file_exist || err != nil {
		return nil_UUID, errors.New("file does not exist or has been changed")
	}
	// append owner node and change share metadata if i am the owner of the file
	if metadata.Owner_node == nil && !metadata.Shared {
		metadata.Owner_node = metadata.Mynode
		// decrypt sharemetadata
	}
	//userlib.DebugMsg("Mynode children: %s", metadata.Mynode.Children)

	// find key of share_metadata

	share_meta_uuid, share_meta_existed := userdata.Share_meta_dict[filename]
	share_meta_enc_key := metadata.Share_enc_key[:16]
	share_meta_hmac_key := metadata.Share_hmac_key[:16]

	_, share_meta_file_existed := userlib.DatastoreGet(share_meta_uuid)
	if !share_meta_existed || !share_meta_file_existed {
		return nil_UUID, errors.New("share metadata does not exist")
	}

	// store the information into the Invitation struct
	var pack Invitation_Package
	var invite Invitation
	invite.Share_Meta_enc_key = share_meta_enc_key
	invite.Share_Meta_hmac_key = share_meta_hmac_key
	invite.Share_Meta_uuid = share_meta_uuid

	// generate the symmetric key
	RSA_enc_key, err := userlib.HashKDF(meta_key, []byte("RSA_Enc"))
	RSA_hmac_key, err := userlib.HashKDF(meta_key, []byte("RSA_Hmac"))

	// get the invitation struct into bytes
	inv_bytes, _ := json.Marshal(invite)
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)

	pack.Enc_invitation, err = Enc_Mac(inv_bytes, RSA_enc_key[:16], RSA_hmac_key[:16], iv)
	pack.RSA_inv_enc_key, err = userlib.PKEEnc(rsa_key, RSA_enc_key)
	pack.RSA_inv_hmac_key, err = userlib.PKEEnc(rsa_key, RSA_hmac_key)
	pack.Sendernode = metadata.Mynode
	if err != nil {
		return nil_UUID, err
	}
	sign_enc, err := userlib.DSSign(userdata.SignKey, pack.RSA_inv_enc_key)
	sign_hmac, err := userlib.DSSign(userdata.SignKey, pack.RSA_inv_hmac_key)
	pack.RSA_inv_enc_key = append(sign_enc, pack.RSA_inv_enc_key...)
	pack.RSA_inv_hmac_key = append(sign_hmac, pack.RSA_inv_hmac_key...)

	pack_bytes, _ := json.Marshal(pack)
	// want out UUID to be from hashed_username, generate it for the new file
	//username || file_uuid
	//username || file_meta_uuid
	sign_to_hash := append(username_b, []byte("sign")...)
	sign_to_hash1 := append(username_a, []byte("sign")...)
	// hash them
	hashed_sign_uuid := userlib.Hash(sign_to_hash)
	hashed_sign_uuid1 := userlib.Hash(sign_to_hash1)
	// hashed || filename
	sign_uuid_1 := append(hashed_sign_uuid, []byte(filename)...)
	sign_uuid_1 = append(sign_uuid_1, hashed_sign_uuid1...)
	// hash again for the UUID
	sign_uuid_2 := userlib.Hash(sign_uuid_1)[:16]

	//translate byte to UUID
	sign_uuid, err := uuid.FromBytes(sign_uuid_2)
	if err != nil {
		return nil_UUID, errors.New("sign fail")
	}
	userlib.DatastoreSet(sign_uuid, pack_bytes)

	// apend my name in tree
	var receiver_node Node
	receiver_node.Username = recipientUsername
	receiver_node.Invite = sign_uuid
	receiver_node.Children = make([]*Node, 0)

	metadata.Owner_node, metadata.Mynode, err = TreeAddChild(metadata.Owner_node, &receiver_node, userdata.Username)
	if err != nil {
		return nil_UUID, err
	}

	//userlib.DebugMsg("Mynode children: %s", metadata.Mynode.Children)

	// store new metadata in datastore
	meta_bytes, err := json.Marshal(metadata)
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_meta, err := Enc_Mac(meta_bytes, meta_enc_key[:16], meta_hmac_key[:16], iv)
	userlib.DatastoreSet(meta_uuid, enc_mac_meta)

	// we need to store the share_metadata so that other users can check it
	share_file, _ := userlib.DatastoreGet(share_meta_uuid)
	share_meta, err := decrypt(share_file, metadata.Share_enc_key[:16], metadata.Share_hmac_key[:16])
	if err != nil {
		return nil_UUID, errors.New("share meta does not exist or has been changed")
	}

	json_err = json.Unmarshal(share_meta, &share_metadata)
	if json_err != nil {
		return nil_UUID, errors.New("seems something wrong about the json")
	}
	// change share metadata
	share_metadata.Owner_node = metadata.Owner_node
	// store share_metadata
	share_meta_bytes, err := json.Marshal(share_metadata)
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	share_enc_mac_meta, err := Enc_Mac(share_meta_bytes, metadata.Share_enc_key[:16], metadata.Share_hmac_key[:16], iv)
	userlib.DatastoreSet(share_meta_uuid, share_enc_mac_meta)

	return sign_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// check the validity of the user first
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	//see whether sender exists
	username_b := []byte(senderUsername)
	sender_to_hash := append(username_b, []byte("uuid")...)
	hashed_sender := userlib.Hash(sender_to_hash)[:16]
	sender_uuid, err := uuid.FromBytes(hashed_sender)
	if err != nil {
		return errors.New("something goes wrong when do frombytes")
	}
	sender_rsa_key := fmt.Sprintf("%s_SIGN", senderUsername)
	_, has_sender := userlib.KeystoreGet(sender_rsa_key)
	_, has_sender_2 := userlib.DatastoreGet(sender_uuid)
	if !has_sender || !has_sender_2 {
		return errors.New("sender does not exist or attackers")
	}

	// check the sign
	var pack Invitation_Package
	pack_byte, exist := userlib.DatastoreGet(invitationPtr)
	if !exist {
		return errors.New("the file does not exist")
	}
	err = json.Unmarshal(pack_byte, &pack)
	if err != nil {
		return err
	}
	// find the sender's sign public key
	user_sign_key := fmt.Sprintf("%s_SIGN", senderUsername)
	verify_key, exist := userlib.KeystoreGet(user_sign_key)

	enc_cipher := pack.RSA_inv_enc_key[256:]
	enc_sign := pack.RSA_inv_enc_key[:256]
	hmac_cipher := pack.RSA_inv_hmac_key[256:]
	hmac_sign := pack.RSA_inv_hmac_key[:256]

	enc_err := userlib.DSVerify(verify_key, enc_cipher, enc_sign)
	hmac_err := userlib.DSVerify(verify_key, hmac_cipher, hmac_sign)
	if enc_err != nil || hmac_err != nil {
		return errors.New("the message has been changed")
	}

	// decrypt the cipher and get invitation
	enc_key, err1 := userlib.PKEDec(userdata.SecretKey, enc_cipher)
	hmac_key, err2 := userlib.PKEDec(userdata.SecretKey, hmac_cipher)
	if err1 != nil || err2 != nil {
		return errors.New("decrypt fail")
	}
	cipher_Inv := pack.Enc_invitation
	invitation_bytes, err := decrypt(cipher_Inv, enc_key[:16], hmac_key[:16])
	if err != nil {
		return err
	}
	var invitation Invitation
	json_err := json.Unmarshal(invitation_bytes, &invitation)
	if json_err != nil {
		return errors.New("unmarshal failed")
	}
	// get the metadata
	//userlib.DebugMsg("The UUID get by the user: %s", invitation.Share_Meta_uuid)

	share_meta_uuid := invitation.Share_Meta_uuid
	share_meta_enc_key := invitation.Share_Meta_enc_key
	share_meta_hmac_key := invitation.Share_Meta_hmac_key
	share_meta_file, exist := userlib.DatastoreGet(share_meta_uuid)

	if !exist {
		return errors.New("share metadata does not exist")
	}
	meta, err := decrypt(share_meta_file, share_meta_enc_key[:16], share_meta_hmac_key[:16])
	if err != nil {
		return err
	}
	var metadata MetaData
	json_err = json.Unmarshal(meta, &metadata)
	//get the file
	file_uuid := metadata.File_uuid
	file_enc_key := metadata.File_enc_key
	file_hmac_key := metadata.File_hmac_key
	_, file_exist := userlib.DatastoreGet(file_uuid)
	if !file_exist {
		return errors.New("file does not exist or has been changed")
	}
	//check the uuid of file and uuid of metadata exists or not

	//store the metadata of the file

	f_uuid, file_dict_existed := userdata.File_meta_dict[filename]
	_, data_existed := userlib.DatastoreGet(f_uuid)
	username_a := []byte(userdata.Username)
	if !file_dict_existed || !data_existed {
		afile_meta_to_hash := append(username_a, []byte("file_meta_uuid")...)

		ahashed_meta_uuid := userlib.Hash(afile_meta_to_hash)

		ameta_uuid_1 := append(ahashed_meta_uuid, []byte(filename)...)

		ameta_uuid_2 := userlib.Hash(ameta_uuid_1)[:16]

		afile_meta_uuid, err := uuid.FromBytes(ameta_uuid_2)
		if err != nil {
			return errors.New("from byte fails")
		}

		//store metadata's uuid in map
		userdata.File_meta_dict[filename] = afile_meta_uuid
		userdata.Share_meta_dict[filename] = share_meta_uuid

		var metadata_recevier MetaData
		metadata_recevier.File_enc_key = file_enc_key
		metadata_recevier.File_hmac_key = file_hmac_key
		metadata_recevier.File_uuid = file_uuid
		metadata_recevier.Iv = metadata.Iv
		metadata_recevier.Slice_size = metadata.Slice_size
		metadata_recevier.Share_enc_key = invitation.Share_Meta_enc_key
		metadata_recevier.Share_hmac_key = invitation.Share_Meta_hmac_key
		metadata_recevier.InvitationPackptr = invitationPtr
		metadata_recevier.Owner_node = metadata.Owner_node
		metadata_recevier.Shared = true
		var mynode Node
		mynode.Username = userdata.Username
		mynode.Invite = invitationPtr
		metadata_recevier.Mynode = &mynode

		//store metadata
		iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
		meta_bytes, _ := json.Marshal(metadata_recevier)
		meta_key := userlib.Argon2Key(userdata.RootKey, ameta_uuid_1, 16)
		meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
		meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))
		enc_mac_meta, err := Enc_Mac(meta_bytes, meta_enc_key[:16], meta_hmac_key[:16], iv)

		userlib.DatastoreSet(afile_meta_uuid, enc_mac_meta)
		//store userdata
		password_b := []byte(userdata.Password)
		username_to_hash := append(username_a, []byte("uuid")...)
		hashed_username := userlib.Hash(username_to_hash)[:16]
		user_uuid, err := uuid.FromBytes(hashed_username)
		RootKey := userlib.Argon2Key(password_b, username_a, 16)
		enc_key, err := userlib.HashKDF(RootKey, []byte("Enc"))
		hmac_key, err := userlib.HashKDF(RootKey, []byte("Hmac"))
		useable_enc_key := enc_key[:16]
		useable_hmac_key := hmac_key[:16]

		bytes, _ := json.Marshal(userdata)
		iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
		enc_mac_bytes, err := Enc_Mac(bytes, useable_enc_key, useable_hmac_key, iv)
		userlib.DatastoreSet(user_uuid, enc_mac_bytes)

	}
	if file_dict_existed || data_existed {
		return errors.New("file already exists")
	}

	//store userdata

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// load the latest version
	userdata, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	//see whether recipient exists
	username_a := []byte(recipientUsername)
	username_to_hash := append(username_a, []byte("uuid")...)
	hashed_username := userlib.Hash(username_to_hash)[:16]
	recuser_uuid, err := uuid.FromBytes(hashed_username)
	if err != nil {
		return errors.New("frombytes fails")
	}
	recuser_rsa_key := fmt.Sprintf("%s_SIGN", recipientUsername)
	_, rechas_user := userlib.KeystoreGet(string(recuser_rsa_key))
	_, rechas_user_2 := userlib.DatastoreGet(recuser_uuid)
	if !rechas_user || !rechas_user_2 {
		return errors.New("recipient does not exist or attackers")
	}
	//see whether file and meta data exist
	f_uuid, file_dict_existed := userdata.File_meta_dict[filename]
	share_meta_uuid, share_meta_existed := userdata.Share_meta_dict[filename]
	meta_file, data_existed := userlib.DatastoreGet(f_uuid)
	share_meta_cipher, share_meta_file_existed := userlib.DatastoreGet(share_meta_uuid)
	if !file_dict_existed || !data_existed {
		return errors.New("file does not exist")
	}
	if !share_meta_existed || !share_meta_file_existed {
		return errors.New("share metadata does not exist")
	}

	// want out UUID to be from hashed_username, generate it for the new file

	username_b := []byte(userdata.Username)

	file_meta_to_hash := append(username_b, []byte("file_meta_uuid")...)

	hashed_meta_uuid := userlib.Hash(file_meta_to_hash)

	meta_uuid_1 := append(hashed_meta_uuid, []byte(filename)...)

	// want to store it in the datastore, we need to deal with the content
	Rootkey := userdata.RootKey

	// enc and hmac meta data struct

	meta_key := userlib.Argon2Key(Rootkey, meta_uuid_1, 16)
	meta_enc_key, err := userlib.HashKDF(meta_key, []byte("Enc"))
	meta_hmac_key, err := userlib.HashKDF(meta_key, []byte("Hmac"))

	meta, err := decrypt(meta_file, meta_enc_key[:16], meta_hmac_key[:16])

	if err != nil {
		return err
	}
	var metadata MetaData
	json_err := json.Unmarshal(meta, &metadata)
	if json_err != nil {
		return errors.New("seems something wrong about the json")
	}

	// owner
	var sharemeta_tmp MetaData
	decrypted_share, err := decrypt(share_meta_cipher, metadata.Share_enc_key, metadata.Share_hmac_key)
	if err != nil {
		return err
	}
	_ = json.Unmarshal(decrypted_share, &sharemeta_tmp)

	// updete the share chain
	metadata.Owner_node = sharemeta_tmp.Owner_node

	if err != nil {
		return err
	}
	// check the file
	//file_enc_key := metadata.File_enc_key
	//file_hmac_key := metadata.File_hmac_key
	file_uuid := metadata.File_uuid
	file_dec, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	//delete original file
	userlib.DatastoreDelete(file_uuid)
	newfile_uuid := uuid.New()
	for {
		_, existsome := userlib.DatastoreGet(newfile_uuid)
		if !existsome {
			break
		}
		newfile_uuid = uuid.New()
	}

	// re-encrypt the file
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	newcontent_enc_key := userlib.Argon2Key(Rootkey, metadata.File_enc_key, 16)
	newcontent_hmac_key := userlib.Argon2Key(Rootkey, metadata.File_hmac_key, 16)

	new_enc_mac_content, err := Enc_Mac(file_dec, newcontent_enc_key[:16], newcontent_hmac_key[:16], iv)
	// store file in datastore
	userlib.DatastoreSet(newfile_uuid, new_enc_mac_content)
	// change uuid of file
	metadata.File_uuid = newfile_uuid
	metadata.File_enc_key = newcontent_enc_key[:16]
	metadata.File_hmac_key = newcontent_hmac_key[:16]
	metadata.Slice_size = []int{len(new_enc_mac_content) - 64}
	// delete share metadata
	userlib.DatastoreDelete(share_meta_uuid)
	// recreate share metadata
	var newmeta MetaData
	newmeta = metadata
	newmeta.Share_enc_key = []byte{}
	newmeta.Share_hmac_key = []byte{}

	// change metadata's key
	share_meta_enc_key := userlib.Argon2Key(Rootkey, metadata.Share_enc_key, 16)
	share_meta_hmac_key := userlib.Argon2Key(Rootkey, metadata.Share_hmac_key, 16)

	// encrypt sharemetadata
	share_meta_bytes, _ := json.Marshal(newmeta)
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_share_meta, err := Enc_Mac(share_meta_bytes, share_meta_enc_key[:16], share_meta_hmac_key[:16], iv)

	afile_share_uuid := uuid.New()
	for {
		_, existsome := userlib.DatastoreGet(afile_share_uuid)
		if !existsome {
			break
		}
		afile_share_uuid = uuid.New()
	}
	userlib.DatastoreSet(afile_share_uuid, enc_mac_share_meta)

	// change share metdadata map
	userdata.Share_meta_dict[filename] = afile_share_uuid
	//change key in metadata
	metadata.Share_enc_key = share_meta_enc_key
	metadata.Share_hmac_key = share_meta_hmac_key
	//see whether file is shared with recipient
	in_share := ChildLocation(metadata.Owner_node.Children, recipientUsername)
	if in_share == -1 {
		return errors.New("Not in share chain")
	}
	// change the key

	// modify the share tree
	metadata.Owner_node, err = RemoveDirectChild(metadata.Owner_node, recipientUsername)
	if err != nil {
		return err
	}

	// generate a new Invitation to be stored in Invitation_package
	var new_invitation Invitation
	new_invitation.Share_Meta_enc_key = metadata.Share_enc_key
	new_invitation.Share_Meta_hmac_key = metadata.Share_hmac_key
	new_invitation.Share_Meta_uuid = afile_share_uuid

	// change Invitation's key
	salt1 := userlib.RandomBytes(256)
	salt2 := userlib.RandomBytes(256)
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	new_inv_enc_key := userlib.Argon2Key(Rootkey, salt1, 16)
	new_inv_hmac_key := userlib.Argon2Key(Rootkey, salt2, 16)
	new_invitation_bytes, err1 := json.Marshal(new_invitation)
	enc_invitation, err := Enc_Mac(new_invitation_bytes, new_inv_enc_key, new_inv_hmac_key, iv)
	if err != nil || err1 != nil {
		return err
	}
	if len(metadata.Owner_node.Children) != 0 {
		// reinvite onther recipients
		metadata.Owner_node, err = Reinvite(metadata.Owner_node, new_inv_enc_key, new_inv_hmac_key, enc_invitation, userdata.SignKey)
	}
	// encrypt the metadata
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	meta_bytes, _ := json.Marshal(metadata)
	enc_mac_meta, err := Enc_Mac(meta_bytes, meta_enc_key[:16], meta_hmac_key[:16], iv)
	// store metadata
	userlib.DatastoreSet(f_uuid, enc_mac_meta)

	// store userdata
	password_b := []byte(userdata.Password)
	busername_to_hash := append(username_b, []byte("uuid")...)
	bhashed_username := userlib.Hash(busername_to_hash)[:16]
	buser_uuid, err := uuid.FromBytes(bhashed_username)
	RootKey := userlib.Argon2Key(password_b, username_b, 16)
	enc_key, err := userlib.HashKDF(RootKey, []byte("Enc"))
	hmac_key, err := userlib.HashKDF(RootKey, []byte("Hmac"))
	useable_enc_key := enc_key[:16]
	useable_hmac_key := hmac_key[:16]

	bytes, _ := json.Marshal(userdata)
	iv = userlib.RandomBytes(userlib.AESBlockSizeBytes)
	enc_mac_bytes, err := Enc_Mac(bytes, useable_enc_key, useable_hmac_key, iv)
	userlib.DatastoreSet(buser_uuid, enc_mac_bytes)

	return nil
}
