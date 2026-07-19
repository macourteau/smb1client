package smb1

import (
	"encoding/asn1"

	"github.com/macourteau/smb1client/internal/ntlm"
	"github.com/macourteau/smb1client/internal/spnego"
)

// Initiator is the interface for session authentication.
// It follows the GSS-API pattern used by go-smb2 for API compatibility.
type Initiator interface {
	oid() asn1.ObjectIdentifier
	initSecContext() ([]byte, error)            // GSS_Init_sec_context
	acceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	sum(bs []byte) []byte                       // GSS_getMIC
	sessionKey() []byte                         // QueryContextAttributes
}

// NTLMInitiator implements NTLM v2 authentication for SMB1 sessions.
// It provides a public wrapper around the internal NTLM client.
//
// You can use either Password or Hash for authentication:
//   - Password: plain text password (will be hashed internally)
//   - Hash: pre-computed NTLM hash (16 bytes, NTOWFv2)
//
// Example:
//
//	initiator := &smb1.NTLMInitiator{
//		User:     "username",
//		Password: "password",
//		Domain:   "WORKGROUP",
//	}
type NTLMInitiator struct {
	// User is the username for authentication.
	// Required field.
	User string

	// Password is the plain text password.
	// Use either Password or Hash, not both.
	Password string

	// Hash is the pre-computed NTLM password hash (16 bytes).
	// Use either Password or Hash, not both.
	// Useful for pass-the-hash attacks or when password is not available.
	Hash []byte

	// Domain is the Windows domain or workgroup name.
	// Defaults to "WORKGROUP" if empty.
	Domain string

	// Workstation is the client workstation name.
	// Defaults to "localhost" if empty.
	Workstation string

	// TargetSPN is the Service Principal Name for the target server.
	// Format: "service/hostname[:port]" (e.g., "cifs/server:445")
	// Optional field.
	TargetSPN string

	// Internal state
	ntlm   *ntlm.Client // internal NTLM client
	seqNum uint32       // sequence number for signing
}

// oid returns the NTLM OID for SPNEGO negotiation.
func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

// initSecContext initializes the NTLM client and generates the negotiate message.
// This is the first step in NTLM authentication.
// For SMB1 extended security, the NTLM message is wrapped in SPNEGO NegTokenInit.
func (i *NTLMInitiator) initSecContext() ([]byte, error) {
	i.ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        i.Hash,
		Domain:      i.Domain,
		Workstation: i.Workstation,
		TargetSPN:   i.TargetSPN,
	}

	// Generate raw NTLM NEGOTIATE message
	nmsg, err := i.ntlm.Negotiate()
	if err != nil {
		return nil, err
	}

	// Wrap in SPNEGO NegTokenInit (required for SMB1 extended security)
	mechTypes := []asn1.ObjectIdentifier{spnego.NlmpOid}
	spnegoToken, err := spnego.EncodeNegTokenInit(mechTypes, nmsg)
	if err != nil {
		return nil, err
	}

	return spnegoToken, nil
}

// acceptSecContext processes the server's challenge and generates the authenticate message.
// This is the second step in NTLM authentication.
// For SMB1 extended security, unwraps the SPNEGO NegTokenResp to get the NTLM CHALLENGE,
// then wraps the NTLM AUTHENTICATE in SPNEGO NegTokenResp.
func (i *NTLMInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	// Unwrap SPNEGO NegTokenResp to get raw NTLM CHALLENGE
	negTokenResp, err := spnego.DecodeNegTokenResp(sc)
	if err != nil {
		return nil, err
	}

	// Process raw NTLM CHALLENGE and generate AUTHENTICATE
	amsg, err := i.ntlm.Authenticate(negTokenResp.ResponseToken)
	if err != nil {
		return nil, err
	}

	// Calculate MechListMIC for integrity (optional but recommended)
	var mechListMIC []byte
	if i.ntlm.Session() != nil {
		mechTypes := []asn1.ObjectIdentifier{spnego.NlmpOid}
		ms, err := asn1.Marshal(mechTypes)
		if err == nil {
			mechListMIC = i.sum(ms)
		}
	}

	// Wrap in SPNEGO NegTokenResp
	spnegoToken, err := spnego.EncodeNegTokenResp(0, nil, amsg, mechListMIC)
	if err != nil {
		return nil, err
	}

	return spnegoToken, nil
}

// sum computes a message integrity check (MIC) for signing.
// SMB1 typically doesn't use signing, but this is kept for API compatibility.
func (i *NTLMInitiator) sum(bs []byte) []byte {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

// sessionKey returns the NTLM session key for encryption/signing.
// SMB1 typically doesn't use encryption, but this is kept for API compatibility.
func (i *NTLMInitiator) sessionKey() []byte {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	return i.ntlm.Session().SessionKey()
}
