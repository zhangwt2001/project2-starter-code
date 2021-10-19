package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	userlib "github.com/cs161-staff/project2-userlib"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// Useful for string mainpulation.
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.

// This function can be safely deleted!
func someUsefulThings() {
	// Creates a random UUID
	f := userlib.UUIDNew()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Works well with Go structures!
	d, _ := userlib.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g userlib.UUID
	userlib.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// errors.New(...) creates an error type!
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

	// Useful for string interpolation.
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
