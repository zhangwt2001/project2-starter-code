package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	//"fmt"

	"encoding/hex"
	_ "encoding/hex"
	_ "errors"

	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const emptyString = ""
const Password1 = "password1"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

func Randomint() int {
	bytes := userlib.RandomBytes(4)
	result := int(0)
	for _, value := range bytes {
		result = (result << 8) | (int(value) & 127)
	}
	return result
}

func getDataStoreSnapshot() map[userlib.UUID][]byte {
	oldDatastore := make(map[userlib.UUID][]byte)
	datastore := userlib.DatastoreGetMap()
	for k, v := range datastore {
		oldDatastore[k] = v
	}
	return oldDatastore
}

func modifyViaDiff(oldDatastore map[userlib.UUID][]byte) map[userlib.UUID][]byte {
	snapshot := getDataStoreSnapshot()
	datastore := userlib.DatastoreGetMap()
	delta := make(map[userlib.UUID][]byte)
	for k, v := range datastore {
		_, ok := oldDatastore[k]
		if !ok {
			newValue := make([]byte, len(v))
			copy(newValue, v)
			newValue[Randomint()%len(newValue)] = byte(Randomint() & 255)
			delta[k] = newValue
		}
	}
	for k, v := range delta {
		userlib.DatastoreSet(k, v)
	}
	return snapshot
}

func getDelta(oldDatastore map[userlib.UUID][]byte) map[userlib.UUID][]byte {
	datastore := userlib.DatastoreGetMap()
	delta := make(map[userlib.UUID][]byte)
	for k, v := range datastore {
		_, ok := oldDatastore[k]
		if !ok {
			newValue := make([]byte, len(v))
			copy(newValue, v)
			newValue[Randomint()%len(newValue)] = byte(Randomint() & 255)
			delta[k] = newValue
		}
	}
	return delta
}

func modifyViaSnapshot(snapshot map[userlib.UUID][]byte) map[userlib.UUID][]byte {
	newSnapshot := getDataStoreSnapshot()
	datastore := userlib.DatastoreGetMap()
	delta := make(map[userlib.UUID][]byte)
	for k := range snapshot {
		value, ok := datastore[k]
		if ok {
			newValue := make([]byte, len(value))
			copy(newValue, value)
			newValue[Randomint()%len(newValue)] = byte(Randomint() & 255)
			delta[k] = newValue
		}
	}
	for k, v := range delta {
		userlib.DatastoreSet(k, v)
	}
	return newSnapshot
}

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var bobLaptop *client.User
	var bobDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(emptyString, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(emptyString, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Integration Test: Testing Single User Store Multiple Times.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte("123qwe"))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte("menqiandaqiaoxiayouguoyiqunya"))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte("kuailaikuailaishuyishuersiliuqiba"))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(emptyString, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(emptyString, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still append to the file.")
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentThree)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Testing Null Username", func() {
			userlib.DebugMsg("Initializing users with empty username.")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Testing create existing user", func() {
			userlib.DebugMsg("Initializing user \"eve\".")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			_, err = client.InitUser("eve", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve a no initialized user", func() {
			userlib.DebugMsg("Retrieve user \"alice\".")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve a user with wrong password", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Retrieve user \"alice\" with password \"%s\".", "#aaaalice#")
			_, err = client.GetUser("alice", "#aaaalice#")
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve user with data affected by malicious actions (data deleted).", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Delete \"alice\"'s user data.")
			userlib.DatastoreClear()

			userlib.DebugMsg("Retrieve deleted user \"alice\".")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve user with data affected by malicious actions (data modified).", func() {
			oldSnapshot := getDataStoreSnapshot()
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Modify \"alice\"'s user data.")
			_ = modifyViaDiff(oldSnapshot)

			userlib.DebugMsg("Retrieve deleted user \"alice\".")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Store file with existing file data affected by malicious actions (data modified).", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Modify file data.")
			_ = modifyViaDiff(oldSnapshot)

			userlib.DebugMsg("Store modified file.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve non-existing file.", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Retrieve non-existing file with filename \"%s\".", aliceFile)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Retrieve with existing file data affected by malicious actions (data modified).", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Modify file data.")
			_ = modifyViaDiff(oldSnapshot)

			userlib.DebugMsg("Retrieve non-existing file with filename \"%s\".", aliceFile)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Append content to non-existing file.", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append content to non-existing file with filename \"%s\".", aliceFile)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Append/Retrieve file when file header was changed due to malicious actions.", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Malicious modifying on file header/configuration.")
			_ = modifyViaDiff(oldSnapshot)

			userlib.DebugMsg("Alice retrieves file with filename \"%s\" whose file header has been maliciously changed.", aliceFile)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appends content to file with filename \"%s\" whose file header has been maliciously changed.", aliceFile)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Sharing non-existing file.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s which does not exist.", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).NotTo(BeNil())
		})

		Specify("Extra Test: Sharing file to non-existing user.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Eve which does not exist for file %s.", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "Eve")
			Expect(err).NotTo(BeNil())
		})

		Specify("Extra Test: Sharing file when file header was changed due to malicious actions.", func() {
			userlib.DebugMsg("Initializing user Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Malicious modifying on file header/configuration.")
			_ = modifyViaDiff(oldSnapshot)

			userlib.DebugMsg("Alice creating invite for Bob for file %s, however file header has been maliciously changed.", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).NotTo(BeNil())
		})

		Specify("Extra Test: Accepting file with filename which has already existed.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			bob.StoreFile(bobFile, []byte(contentTwo))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s which has already existed.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).NotTo(BeNil())
		})

		Specify("Extra Test: Accepting a revoked invitation.", func() {
			userlib.DebugMsg("Initializing users Alice and Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Eve for file %s.", aliceFile, eveFile)
			invite, err := alice.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Eve's access for file %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts an invitation which has been revoked.")
			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).NotTo(BeNil())
		})

		Specify("Extra Test: Accepting a invitation which is for others.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Charles for file %s.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("frank accepts an invitation which is for Charles.")
			err = frank.AcceptInvitation("alice", invite, frankFile)
			Expect(err).NotTo(BeNil())
		})

		// Flag 23
		Specify("Extra Test: Revoking a file which does not exist.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes Bob's access for file %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Revoking a user's access who does not share the file.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice revokes Charles's access for file %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Zero length password.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob and Charles.")
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", emptyString)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", emptyString)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", emptyString, emptyString)
			alice.StoreFile(emptyString, []byte(emptyString))

			userlib.DebugMsg("Alice append empty string to %s", emptyString)
			err = alice.AppendToFile(emptyString, []byte(emptyString))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(emptyString)))
		})

		Specify("Extra Test: Test bandwidth.", func() {
			maxUser := 10
			maxUserNameLen := 50
			maxFileNum := 2
			maxFileNameLen := 500
			users := make([]*client.User, maxUser)
			username := make([]string, maxUser)
			usersFileName := make([][]string, maxUser)

			userlib.DebugMsg("Initializing users.")
			for i := 0; i < maxUser; i++ {
				username[i] = hex.EncodeToString(userlib.RandomBytes(Randomint()%maxUserNameLen + 1))
				users[i], err = client.InitUser(username[i], "password")
				Expect(err).To(BeNil())
			}

			userlib.DebugMsg("Initializing files.")
			for i := 0; i < maxUser; i++ {
				usersFileName[i] = make([]string, maxFileNum)
				for j := 0; j < maxFileNum; j++ {
					usersFileName[i][j] = hex.EncodeToString(userlib.RandomBytes(maxFileNameLen))
					err = users[i].StoreFile(usersFileName[i][j], userlib.RandomBytes(64))
					Expect(err).To(BeNil())
				}
			}

			userlib.DebugMsg("Initializing sharing.")
			for i := 1; i < maxUser; i++ {
				faIndex := Randomint() % i

				invite, err := users[faIndex].CreateInvitation(usersFileName[faIndex][Randomint()%len(usersFileName[faIndex])], username[i])
				Expect(err).To(BeNil())

				newFileName := hex.EncodeToString(userlib.RandomBytes(maxFileNameLen))
				err = users[i].AcceptInvitation(username[faIndex], invite, newFileName)
				Expect(err).To(BeNil())

				usersFileName[i] = append(usersFileName[i], newFileName)
			}

		})

		// Flag 9, 15
		Specify("Extra Test: Retrieve with existing file data affected by malicious actions (user data modified).", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Modify user data")
			_ = modifyViaSnapshot(oldSnapshot)

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Username should be case sensitive.", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"Alice\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"bob\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"Bob\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"charles\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"Charles\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("Charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"eve\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"Eve\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("Eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"frank\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"Frank\" with password \"%s\".", defaultPassword)
			_, err = client.InitUser("Frank", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Extra Test: Operation on sharing file which was affected by malicious actions", func() {
			userlib.DebugMsg("Initializing user \"alice\" with password \"%s\".", defaultPassword)
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"bob\" with password \"%s\".", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user \"charles\" with password \"%s\".", defaultPassword)
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file data: %s into %s", contentOne, aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invitation of %s to Bob.", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			oldSnapshot := getDataStoreSnapshot()

			userlib.DebugMsg("Bob accepts Alice's invitation and stores it as %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			delta := getDelta(oldSnapshot)

			userlib.DebugMsg("Bob appends \"%s\" into %s.", contentTwo, bobFile)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appends \"%s\" into %s.", contentThree, aliceFile)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			_ = modifyViaSnapshot(delta)

			userlib.DebugMsg("Bob appends \"foo\" into %s which data has been modified.", bobFile)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Bob load file %s which data has been modified.", bobFile)
			_, err = bob.LoadFile(bobFile)
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Alice revokes Bob's access of %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
		})

		Specify("Extra Test: Sharing after being revoked.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s when Bob's access has been revoked.", bobFile)
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).NotTo(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users: bob and charles cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Extra Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie and Doris.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err := client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err := client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			frank, err := client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Eve for file %s, and Charlie accepting invite under name %s.", bobFile, eveFile)
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve creating invite for Frank for file %s, and Frank accepting invite under name %s.", eveFile, frankFile)
			invite, err = eve.CreateInvitation(eveFile, "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("eve", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Frank can load the file.")
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles/eve lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Describe("Invitation Chain", func() {
			Specify("Testing multiple divices for create invitation", func() {
				userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
				aliceDesktop, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				bobLaptop, err = client.InitUser("bob", Password1)
				Expect(err).To(BeNil())

				aliceLaptop, err = client.GetUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
				err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("aliceLaptop creating invite for Bob.")
				invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
				err = bobLaptop.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting second instance of Bob - bobDesktop")
				bobDesktop, err = client.GetUser("bob", Password1)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that bobDesktop sees expected file data.")
				data, err := bobDesktop.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))
			})
			Specify("Testing Revoke Functionality", func() {
				userlib.DebugMsg("Initializing users Alice, Bob, Charlie and Doris.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				bob, err = client.InitUser("bob", Password1)
				Expect(err).To(BeNil())

				charles, err = client.InitUser("charles", defaultPassword)
				Expect(err).To(BeNil())

				doris, err = client.InitUser("doris", Password1)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
				alice.StoreFile(aliceFile, []byte(contentOne))

				userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

				invite, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Alice can still load the file.")
				data, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Checking that Bob can load the file.")
				data, err = bob.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
				invite, err = alice.CreateInvitation(aliceFile, "charles")
				Expect(err).To(BeNil())

				err = charles.AcceptInvitation("alice", invite, charlesFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Charles can load the file.")
				data, err = charles.LoadFile(charlesFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Charles creating invite for Doris for file %s, and Doris accepting invite under name %s.", charlesFile, dorisFile)
				invite, err = charles.CreateInvitation(charlesFile, "doris")
				Expect(err).To(BeNil())

				err = doris.AcceptInvitation("charles", invite, dorisFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
				err = alice.RevokeAccess(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that Alice can still load the file.")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Checking that Bob lost access to the file.")
				_, err = bob.LoadFile(bobFile)
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("Checking that Charles can still load the file.")
				_, err = charles.LoadFile(charlesFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
				err = bob.AppendToFile(bobFile, []byte(contentTwo))
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("Checking that Charles can still append to the file.")
				err = charles.AppendToFile(charlesFile, []byte(contentTwo))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting second instance of Bob - bobDesktop")
				bobDesktop, err = client.GetUser("bob", Password1)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bod storing file %s with content: %s", bobFile, contentThree)
				err = bobDesktop.StoreFile(bobFile, []byte(contentThree))
				Expect(err).ToNot(BeNil())

				userlib.DebugMsg("Checking Alice can load the file correctly")
				data, err = alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo)))

				userlib.DebugMsg("Checking Doris can load the file correctly")
				data, err = doris.LoadFile(dorisFile)
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			})
		})
		Describe("Password", func() {

			Describe("Username and Passowrd Tests", func() {

				Specify("Testing unique username.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 2: Testing case-sensitive.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("Alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Initializing user alice.")
					alice, err = client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 3: Testing length of username is zero.", func() {
					userlib.DebugMsg("Initializing user .")
					alice, err = client.InitUser("", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 4: Testing get a user never exists.", func() {
					userlib.DebugMsg("Getting user.")
					alice, err = client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 5: Testing get a empty username.", func() {
					userlib.DebugMsg("Getting user.")
					alice, err = client.GetUser("", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 6: Testing user credentials are invalid.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("Alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Getting user.")
					alice, err = client.GetUser("", "")
					Expect(err).ToNot(BeNil())
				})
				Specify("Test 7: Testing Unable to get user structure due to malicious operation.", func() {
					userlib.DebugMsg("Initializing user alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					all_user := userlib.DatastoreGetMap()
					for k := range all_user {
						all_user[k] = []byte("")
					}

					userlib.DebugMsg("Getting user Alice.")
					aliceLaptop, err = client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
			})

			Describe("Store Tests", func() {

				Specify("Test 1: Different have same filename files.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentTwo)
					err = alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentThree)
					err = alice.AppendToFile(aliceFile, []byte(contentThree))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("Bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = bob.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentTwo)
					err = bob.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

					userlib.DebugMsg("Loading file...")
					data1, err := bob.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data1).To(Equal([]byte(contentOne + contentTwo)))
				})

				Specify("Test 2: Users can have multiple active user sessions at once..", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Initializing user AliceLaptop.")
					aliceLaptop, err = client.GetUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Appending file data: %s", contentTwo)
					err = alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())
				})
			})

			Describe("Load Tests", func() {

				Specify("Test 1: Users can have multiple active user sessions at once.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentTwo)
					err = alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentThree)
					err = alice.AppendToFile(aliceFile, []byte(contentThree))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting user Alice.")
					aliceLaptop, err = client.GetUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					data, err := aliceLaptop.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
				})

				Specify("Test 2: The given filename does not exist in the personal file", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					_, err := aliceLaptop.LoadFile("aliceFile")
					Expect(err).ToNot(BeNil())
				})

			})

			Describe("Load Tests", func() {

				Specify("Test 1: Users can have multiple active user sessions at once.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentTwo)
					err = alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentThree)
					err = alice.AppendToFile(aliceFile, []byte(contentThree))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting user Alice.")
					aliceLaptop, err = client.GetUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					data, err := aliceLaptop.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
				})

				Specify("Test 2: The given filename does not exist in the personal file", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					_, err := aliceLaptop.LoadFile("aliceFile")
					Expect(err).ToNot(BeNil())
				})

			})

			Describe("AcceptInvitation Tests", func() {
				Specify("Test 1 The caller already has a file with the given filename in their personal file namespace.	", func() {
					userlib.DebugMsg("Initializing users Alice, Bob.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentOne)
					bob.StoreFile(bobFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Test 2 The caller is unable to verify that the secure file share invitation pointed to by the given invitationPtr was created by senderUsername	", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					dsmap := userlib.DatastoreGetMap()
					dsmap[invite] = []byte("")

					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})
			})

			Describe("Rovoke Tests", func() {
				Specify("Test 1 Revoke the given filename does not exist.", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).ToNot(BeNil())

				})
				Specify("Test 2 user shouldn't be able to accept invitation after being revoked", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())
					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))
					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())
					userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
					userlib.DebugMsg("Checking that Bob lost access to the file.")
					_, err = bob.LoadFile(bobFile)
					Expect(err).ToNot(BeNil())
					userlib.DebugMsg("Checking that Alice can still load the file.")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})
			})

			Describe("CreateInvitation Tests", func() {
				Specify("Test 1 The given filename does not exist in the personal file namespace of the caller.", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())
					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))
					userlib.DatastoreClear()
					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
					_, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).ToNot(BeNil())
				})
			})

			Specify("Test 2 The given recipientUsername does not exist", func() {
				userlib.DebugMsg("Initializing users Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
				alice.StoreFile(aliceFile, []byte(contentOne))

				userlib.DebugMsg("Alice creating invite for nobody for file %s.", aliceFile)

				_, err := alice.CreateInvitation(aliceFile, "nobody")
				Expect(err).ToNot(BeNil())
			})

			Describe("Edge case: unaccepted invitation", func() {
				Specify("Invitation remains valid after revocation if not accepted", func() {
					userlib.DebugMsg("Initializing Alice and Bob")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice creates aliceFile.txt.")
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice generates an invitation for Bob on aliceFile.")
					_, err = alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice generates an invitation for Charles on aliceFile.")
					alice_invite_charles, err := alice.CreateInvitation(aliceFile, "charles")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice revokes access for Bob before Bob accepts the invitation.")
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Verify that Charles' invitation is still valid.")
					err = charles.AcceptInvitation("alice", alice_invite_charles, charlesFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Ensure Charles can load the file.")
					data, err := charles.LoadFile(charlesFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})
			})

			BeforeEach(func() {
				userlib.DatastoreClear()
				userlib.KeystoreClear()
			})

			Describe("Integration Tests", func() {
				measureBandwidth := func(probe func()) (bandwidth int) {
					before := userlib.DatastoreGetBandwidth()
					probe()
					after := userlib.DatastoreGetBandwidth()
					return after - before
				}

				Specify("Integration Test: Testing Append Efficiency, harder", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err := client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					singleAppend := func() {
						userlib.DebugMsg("Appending file data: %s", contentTwo)
						err = alice.AppendToFile(aliceFile, []byte(contentTwo))
						Expect(err).To(BeNil())
					}

					bw := measureBandwidth(singleAppend)

					multiAppends := func() {
						userlib.DebugMsg("Appending file data 200x: %s", contentTwo)
						for i := 0; i < 50; i++ {
							singleAppend()
						}
					}

					bw2 := measureBandwidth(multiAppends)

					Expect(float64(bw2)).To(BeNumerically("<=", float64(3.91*float64(50)*float64(bw)))) //log50 ~ 3.91
				})

				Specify("Integration Test: Testing Append Efficiency, harder", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err := client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					singleAppend := func() {
						userlib.DebugMsg("Appending file data: %s", contentTwo)
						err = alice.AppendToFile(aliceFile, []byte(contentTwo))
						Expect(err).To(BeNil())
					}

					bw := measureBandwidth(singleAppend)

					multiAppends := func() {
						userlib.DebugMsg("Appending file data 200x: %s", contentTwo)
						for i := 0; i < 200; i++ {
							singleAppend()
						}
					}

					bw2 := measureBandwidth(multiAppends)

					Expect(float64(bw2)).To(BeNumerically("<=", float64(5.29*float64(200)*float64(bw)))) //log200 ~5.29
				})

				Specify("Integrations Test: Getting Nonexistent File", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading nonexistent file")
					_, err := alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Integrations Test: Zero Length Filename", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(emptyString, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					data, err := alice.LoadFile(emptyString)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})

				Specify("Integrations Test: Appending To Nonexistent File", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending file data: %s", contentOne)
					err = alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).ToNot(BeNil())
				})

				Specify("Integrations Test: Get User With Incorrect Password", func() {
					userlib.DebugMsg("Initializing user Alice")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting user Alice with incorrect password.")
					aliceLaptop, err = client.GetUser("alice", "incorrect password")
					Expect(err).ToNot(BeNil())
				})

				Specify("Integrations Test: Init/Get User With Empty Password", func() {
					userlib.DebugMsg("Initializing user Alice with empty password")
					alice, err = client.InitUser("alice", emptyString)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting user Alice with empty password.")
					alice, err = client.GetUser("alice", emptyString)
					Expect(err).To(BeNil())
				})

				Specify("Integrations Test: Appending Empty Byte Array", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Storing file data: %s", contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Appending empty string", emptyString)
					err = alice.AppendToFile(aliceFile, []byte(emptyString))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading file...")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})

				Specify("Integrations Test: Creating Invitation to Revoked File", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob creating invite for Charles for revoked file %s", bobFile)
					invite, err = bob.CreateInvitation(bobFile, "charles")
					Expect(err).ToNot(BeNil())
				})

				Specify("Integrations Test: Creating Invitation to File That Doesn't Exist In User's Namespace", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", "Wrong Filename", bobFile)
					_, err := alice.CreateInvitation("Wrong Filename", "bob")
					Expect(err).ToNot(BeNil())
				})

				Specify("Integrations Test: Creating Invitation to Nonexistent User", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite to nonexistent user", bobFile)
					_, err := alice.CreateInvitation(aliceFile, "Nonexistent User")
					Expect(err).ToNot(BeNil())
				})

				Specify("Integration Test: Accept Invitation With Wrong Invitation UUID", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
					invite1, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob accepting Alice's invite under name %s.", bobFile)
					err = bob.AcceptInvitation("alice", invite1, bobFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob creating invite for Charlie for file %s.", bobFile)
					_, err = bob.CreateInvitation(bobFile, "charles")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie attempting to accept Bob's invite with wrong UUID.")
					err = charles.AcceptInvitation("bob", invite1, charlesFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Integration Test: Accept Invitation for Correct UUID but Wrong Username", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					err = bob.AcceptInvitation("charles", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Integration Test: Accept Invitation for Correct UUID but Non-Existent User", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					err = bob.AcceptInvitation("", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Integration Test: Accept Invitation For Correct Invitation UUID and Username but Wrong Recipient", func() {
					userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
					alice.StoreFile(aliceFile, []byte(contentOne))

					userlib.DebugMsg("Alice creating invite for Bob for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					err = charles.AcceptInvitation("alice", invite, charlesFile)
					Expect(err).ToNot(BeNil())
				})
			})
		})
	})
})
