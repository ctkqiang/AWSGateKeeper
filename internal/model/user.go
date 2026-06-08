package model

type (
	UserType       int
	UserPriviledge int
)

const (
	Owner UserType = iota
	Interal
	External
	Temporary
)

const (
	Root UserPriviledge = iota
	SOCAnalyst
	FrontEndDeveloper
	BackEndDeveloper
	DeploymentOperation
	ThridPartyFrontEndDeveloper
	ThridPartyBackEndDeveloper
	BillingOnly
)

type User struct {
	ID string `json:"id"`

	Type       UserType       `json:"type"`
	Priviledge UserPriviledge `json:"priviledge"`
}
