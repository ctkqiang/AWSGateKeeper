package aws

type (
	ActionGroup string
	Action      string
)

type Policy struct {
	ActionGroup ActionGroup
	Action      Action
}

// Action groups (AWS service prefixes)
const (
	EC2            ActionGroup = "ec2"
	S3             ActionGroup = "s3"
	IAM            ActionGroup = "iam"
	Lambda         ActionGroup = "lambda"
	DynamoDB       ActionGroup = "dynamodb"
	Logs           ActionGroup = "logs"
	CloudFront     ActionGroup = "cloudfront"
	APIGateway     ActionGroup = "apigateway"
	STS            ActionGroup = "sts"
	SQS            ActionGroup = "sqs"
	CloudWatch     ActionGroup = "cloudwatch"
	Billing        ActionGroup = "aws-portal"
	CostExplorer   ActionGroup = "ce"
	CloudTrail     ActionGroup = "cloudtrail"
	GuardDuty      ActionGroup = "guardduty"
	CodeDeploy     ActionGroup = "codedeploy"
	CodePipeline   ActionGroup = "codepipeline"
	CloudFormation ActionGroup = "cloudformation"
	ECS            ActionGroup = "ecs"
	ECR            ActionGroup = "ecr"
)

// Actions (grouped by service)

// EC2
const (
	EC2DescribeInstances             Action = "DescribeInstances"
	EC2RunInstances                  Action = "RunInstances"
	EC2TerminateInstances            Action = "TerminateInstances"
	EC2StartInstances                Action = "StartInstances"
	EC2StopInstances                 Action = "StopInstances"
	EC2CreateSecurityGroup           Action = "CreateSecurityGroup"
	EC2AuthorizeSecurityGroupIngress Action = "AuthorizeSecurityGroupIngress"
)

// S3
const (
	S3ListBuckets       Action = "ListBuckets"
	S3GetObject         Action = "GetObject"
	S3PutObject         Action = "PutObject"
	S3DeleteObject      Action = "DeleteObject"
	S3CopyObject        Action = "CopyObject"
	S3GetBucketLocation Action = "GetBucketLocation"
	S3PutBucketPolicy   Action = "PutBucketPolicy"
)

// IAM
const (
	IAMListUsers        Action = "ListUsers"
	IAMListRoles        Action = "ListRoles"
	IAMCreateRole       Action = "CreateRole"
	IAMAttachRolePolicy Action = "AttachRolePolicy"
	IAMPutRolePolicy    Action = "PutRolePolicy"
	IAMPassRole         Action = "PassRole"
)

// Lambda
const (
	LambdaInvokeFunction     Action = "InvokeFunction"
	LambdaCreateFunction     Action = "CreateFunction"
	LambdaUpdateFunctionCode Action = "UpdateFunctionCode"
	LambdaGetFunction        Action = "GetFunction"
	LambdaListFunctions      Action = "ListFunctions"
)

// DynamoDB
const (
	DynamoDBGetItem     Action = "GetItem"
	DynamoDBPutItem     Action = "PutItem"
	DynamoDBUpdateItem  Action = "UpdateItem"
	DynamoDBDeleteItem  Action = "DeleteItem"
	DynamoDBQuery       Action = "Query"
	DynamoDBScan        Action = "Scan"
	DynamoDBCreateTable Action = "CreateTable"
)

// CloudWatch Logs
const (
	LogsCreateLogGroup     Action = "CreateLogGroup"
	LogsCreateLogStream    Action = "CreateLogStream"
	LogsPutLogEvents       Action = "PutLogEvents"
	LogsDescribeLogGroups  Action = "DescribeLogGroups"
	LogsDescribeLogStreams Action = "DescribeLogStreams"
	LogsGetLogEvents       Action = "GetLogEvents"
	LogsFilterLogEvents    Action = "FilterLogEvents"
)

// CloudFront
const (
	CloudFrontGetDistribution    Action = "GetDistribution"
	CloudFrontCreateInvalidation Action = "CreateInvalidation"
	CloudFrontListDistributions  Action = "ListDistributions"
)

// API Gateway
const (
	APIGatewayGET    Action = "GET"
	APIGatewayPOST   Action = "POST"
	APIGatewayPUT    Action = "PUT"
	APIGatewayDELETE Action = "DELETE"
)

// STS
const (
	STSAssumeRole Action = "AssumeRole"
)

// SQS
const (
	SQSSendMessage    Action = "SendMessage"
	SQSReceiveMessage Action = "ReceiveMessage"
	SQSDeleteMessage  Action = "DeleteMessage"
	SQSCreateQueue    Action = "CreateQueue"
)

// CloudWatch metrics
const (
	CloudWatchListMetrics    Action = "ListMetrics"
	CloudWatchGetMetricData  Action = "GetMetricData"
	CloudWatchPutMetricData  Action = "PutMetricData"
	CloudWatchDescribeAlarms Action = "DescribeAlarms"
)

// Billing & Cost Explorer
const (
	BillingViewBilling          Action = "ViewBilling"
	BillingViewUsage            Action = "ViewUsage"
	CostExplorerGetCostAndUsage Action = "GetCostAndUsage"
)

// CloudTrail
const (
	CloudTrailLookupEvents      Action = "LookupEvents"
	CloudTrailDescribeTrails    Action = "DescribeTrails"
	CloudTrailGetTrailStatus    Action = "GetTrailStatus"
	CloudTrailGetEventSelectors Action = "GetEventSelectors"
	CloudTrailCreateTrail       Action = "CreateTrail"
)

// GuardDuty
const (
	GuardDutyListFindings    Action = "ListFindings"
	GuardDutyGetFindings     Action = "GetFindings"
	GuardDutyListDetectors   Action = "ListDetectors"
	GuardDutyArchiveFindings Action = "ArchiveFindings"
	GuardDutyCreateDetector  Action = "CreateDetector"
)

// CodeDeploy
const (
	CodeDeployListApplications Action = "ListApplications"
	CodeDeployGetApplication   Action = "GetApplication"
	CodeDeployCreateDeployment Action = "CreateDeployment"
	CodeDeployListDeployments  Action = "ListDeployments"
	CodeDeployGetDeployment    Action = "GetDeployment"
)

// CodePipeline
const (
	CodePipelineListPipelines          Action = "ListPipelines"
	CodePipelineGetPipeline            Action = "GetPipeline"
	CodePipelineStartPipelineExecution Action = "StartPipelineExecution"
	CodePipelineGetPipelineExecution   Action = "GetPipelineExecution"
)

// CloudFormation
const (
	CloudFormationListStacks          Action = "ListStacks"
	CloudFormationDescribeStacks      Action = "DescribeStacks"
	CloudFormationCreateStack         Action = "CreateStack"
	CloudFormationUpdateStack         Action = "UpdateStack"
	CloudFormationDeleteStack         Action = "DeleteStack"
	CloudFormationDescribeStackEvents Action = "DescribeStackEvents"
)

// ECS
const (
	ECSListClusters     Action = "ListClusters"
	ECSDescribeClusters Action = "DescribeClusters"
	ECSListServices     Action = "ListServices"
	ECSDescribeServices Action = "DescribeServices"
	ECSRunTask          Action = "RunTask"
	ECSDescribeTasks    Action = "DescribeTasks"
)

// ECR
const (
	ECRDescribeRepositories  Action = "DescribeRepositories"
	ECRListImages            Action = "ListImages"
	ECRDescribeImages        Action = "DescribeImages"
	ECRGetAuthorizationToken Action = "GetAuthorizationToken"
	ECRBatchGetImage         Action = "BatchGetImage"
)

// Action group registry.
var groupActions = map[ActionGroup][]Action{
	EC2: {
		EC2DescribeInstances,
		EC2RunInstances,
		EC2TerminateInstances,
		EC2StartInstances,
		EC2StopInstances,
		EC2CreateSecurityGroup,
		EC2AuthorizeSecurityGroupIngress,
	},
	S3: {
		S3ListBuckets,
		S3GetObject,
		S3PutObject,
		S3DeleteObject,
		S3CopyObject,
		S3GetBucketLocation,
		S3PutBucketPolicy,
	},
	IAM: {
		IAMListUsers,
		IAMListRoles,
		IAMCreateRole,
		IAMAttachRolePolicy,
		IAMPutRolePolicy,
		IAMPassRole,
	},
	Lambda: {
		LambdaInvokeFunction,
		LambdaCreateFunction,
		LambdaUpdateFunctionCode,
		LambdaGetFunction,
		LambdaListFunctions,
	},
	DynamoDB: {
		DynamoDBGetItem,
		DynamoDBPutItem,
		DynamoDBUpdateItem,
		DynamoDBDeleteItem,
		DynamoDBQuery,
		DynamoDBScan,
		DynamoDBCreateTable,
	},
	Logs: {
		LogsCreateLogGroup,
		LogsCreateLogStream,
		LogsPutLogEvents,
		LogsDescribeLogGroups,
		LogsDescribeLogStreams,
		LogsGetLogEvents,
		LogsFilterLogEvents,
	},
	CloudFront: {
		CloudFrontGetDistribution,
		CloudFrontCreateInvalidation,
		CloudFrontListDistributions,
	},
	APIGateway: {
		APIGatewayGET,
		APIGatewayPOST,
		APIGatewayPUT,
		APIGatewayDELETE,
	},
	STS: {
		STSAssumeRole,
	},
	SQS: {
		SQSSendMessage,
		SQSReceiveMessage,
		SQSDeleteMessage,
		SQSCreateQueue,
	},
	CloudWatch: {
		CloudWatchListMetrics,
		CloudWatchGetMetricData,
		CloudWatchPutMetricData,
		CloudWatchDescribeAlarms,
	},
	Billing: {
		BillingViewBilling,
		BillingViewUsage,
	},
	CostExplorer: {
		CostExplorerGetCostAndUsage,
	},
	CloudTrail: {
		CloudTrailLookupEvents,
		CloudTrailDescribeTrails,
		CloudTrailGetTrailStatus,
		CloudTrailGetEventSelectors,
		CloudTrailCreateTrail,
	},
	GuardDuty: {
		GuardDutyListFindings,
		GuardDutyGetFindings,
		GuardDutyListDetectors,
		GuardDutyArchiveFindings,
		GuardDutyCreateDetector,
	},
	CodeDeploy: {
		CodeDeployListApplications,
		CodeDeployGetApplication,
		CodeDeployCreateDeployment,
		CodeDeployListDeployments,
		CodeDeployGetDeployment,
	},
	CodePipeline: {
		CodePipelineListPipelines,
		CodePipelineGetPipeline,
		CodePipelineStartPipelineExecution,
		CodePipelineGetPipelineExecution,
	},
	CloudFormation: {
		CloudFormationListStacks,
		CloudFormationDescribeStacks,
		CloudFormationCreateStack,
		CloudFormationUpdateStack,
		CloudFormationDeleteStack,
		CloudFormationDescribeStackEvents,
	},
	ECS: {
		ECSListClusters,
		ECSDescribeClusters,
		ECSListServices,
		ECSDescribeServices,
		ECSRunTask,
		ECSDescribeTasks,
	},
	ECR: {
		ECRDescribeRepositories,
		ECRListImages,
		ECRDescribeImages,
		ECRGetAuthorizationToken,
		ECRBatchGetImage,
	},
}

// FullAction returns the fully qualified AWS action string, e.g.
// "ec2:DescribeInstances".
func (p Policy) FullAction() string {
	return string(p.ActionGroup) + ":" + string(p.Action)
}

// GetActionNames returns the AWS API action names belonging to an
// ActionGroup, e.g. GetActionNames(S3) returns ["ListBuckets", "GetObject",
// ...].
func GetActionNames(group ActionGroup) []string {
	actions, ok := groupActions[group]
	if !ok {
		return nil
	}
	names := make([]string, len(actions))
	for i, a := range actions {
		names[i] = string(a)
	}
	return names
}

// GetFullActionsForGroup returns fully qualified action strings for every
// action in the given group, e.g. GetFullActionsForGroup(S3) returns
// ["s3:ListBuckets", "s3:GetObject", ...].
func GetFullActionsForGroup(group ActionGroup) []string {
	actions, ok := groupActions[group]
	if !ok {
		return nil
	}
	full := make([]string, len(actions))
	for i, a := range actions {
		full[i] = string(group) + ":" + string(a)
	}
	return full
}
