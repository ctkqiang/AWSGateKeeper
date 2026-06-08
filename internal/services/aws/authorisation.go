package services

import (
	"context"
	"sync"
	"time"

	aws_config "github.com/aws/aws-sdk-go-v2/config"
)

type Account struct {
	cfg      aws_config.Config // reusable AWS SDK config for all service clients
	identity CallerIdentity    // verified caller identity from STS
	ready    bool              // true after successful Init()
	mu       sync.RWMutex      // protects all fields
	initErr  error             // captured error from the Init process
}

type CallerIdentity struct {
	AccountID  string    // 12-digit AWS account ID
	ARN        string    // IAM role or user ARN, e.g. arn:aws:sts::123456789012:assumed-role/admin
	UserID     string    // unique user/role ID, e.g. AROA...
	Verified   bool      // true if STS returned a valid identity
	VerifiedAt time.Time // timestamp of last successful STS verification
}

var (
	globalAccount *Account
	globalMu      sync.Mutex
)

func Init(ctx context.Context) error {
	// var options []func(*aws_config.LoadOptions) error

	// globalMu.Lock()
	// defer globalMu.Unlock()

	// account := &Account{}

	return nil
}

func AWSAuthorisation() {

}
