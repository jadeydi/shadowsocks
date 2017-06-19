package shadow

import "fmt"

type Error byte

func (err Error) Error() string {
	return fmt.Sprintf("SOCKS error: %d", err)
}

const (
	ServerFailureError        = Error(1)
	ConnectionNotAllowedError = Error(2)
	NetworkUnreachableError   = Error(3)
	HostUnreachableError      = Error(4)
	ConnectionRefusedError    = Error(5)
	TTLExpiredError           = Error(6)
	CommandNotSupportedError  = Error(7)
	AddressNotSupportedError  = Error(8)
)