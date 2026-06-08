package aws

import "aws_gatekeeper/internal/model"

func roleName(priviledge model.UserPriviledge) string {
	names := map[model.UserPriviledge]string{
		model.Root:                        "RootRole",
		model.SOCAnalyst:                  "SOCAnalystRole",
		model.FrontEndDeveloper:           "FrontEndDeveloperRole",
		model.BackEndDeveloper:            "BackEndDeveloperRole",
		model.DeploymentOperation:         "DeploymentOperationRole",
		model.ThridPartyFrontEndDeveloper: "ThirdPartyFrontEndDeveloperRole",
		model.ThridPartyBackEndDeveloper:  "ThirdPartyBackEndDeveloperRole",
		model.BillingOnly:                 "BillingOnlyRole",
	}

	return names[priviledge]
}
