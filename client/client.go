package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	userlib "github.com/cs161-staff/project2-userlib"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

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
	randomUUID := userlib.UUIDNew()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	deterministicUUID := userlib.UUIDFromBytes([]byte("user-structs/alice"))
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor string
	}
	course := Course{"CS 161", "Nicholas Weaver"}
	courseBytes, err := userlib.Marshal(course)
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors!
		panic(errors.New("An error occurred while marshalling a course: " + err.Error()))
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// A useful function for string interpolation.
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// User is the structure definition for a user record.
type User struct {
	Username string

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	// TODO: This is a toy implementation.
	userdata.Username = username

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// TODO: This is a toy implementation.
	storageKey, _ := userlib.UUIDFromBytes([]byte(filename + userdata.Username))
	jsonData, _ := userlib.Marshal(content)
	userlib.DatastoreSet(storageKey, jsonData)

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {

	// TODO: This is a toy implementation.
	storageKey, _ := userlib.UUIDFromBytes([]byte(filename + userdata.Username))
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	userlib.Unmarshal(dataJSON, &content)
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr userlib.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr userlib.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
