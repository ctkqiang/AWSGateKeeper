package aws

type (
	ActionGroup string
	Action      string
)

type Policy struct {
	ActionGroup ActionGroup
	Action      Action
}

// Action groups (service prefixes)
const (
	EC2          ActionGroup = "ec2"
	S3           ActionGroup = "s3"
	IAM          ActionGroup = "iam"
	Lambda       ActionGroup = "lambda"
	DynamoDB     ActionGroup = "dynamodb"
	Logs         ActionGroup = "logs"
	CloudFront   ActionGroup = "cloudfront"
	APIGateway   ActionGroup = "apigateway"
	STS          ActionGroup = "sts"
	SQS          ActionGroup = "sqs"
	CloudWatch   ActionGroup = "cloudwatch"
	Billing      ActionGroup = "aws-portal" // old billing actions
	CostExplorer ActionGroup = "ce"         // Cost Explorer
)

// EC2 actions
const (
	EC2DescribeInstances             Action = "DescribeInstances"
	EC2RunInstances                  Action = "RunInstances"
	EC2TerminateInstances            Action = "TerminateInstances"
	EC2StartInstances                Action = "StartInstances"
	EC2StopInstances                 Action = "StopInstances"
	EC2CreateSecurityGroup           Action = "CreateSecurityGroup"
	EC2AuthorizeSecurityGroupIngress Action = "AuthorizeSecurityGroupIngress"
)

// S3 actions
const (
	S3ListBuckets       Action = "ListBuckets"
	S3GetObject         Action = "GetObject"
	S3PutObject         Action = "PutObject"
	S3DeleteObject      Action = "DeleteObject"
	S3CopyObject        Action = "CopyObject"
	S3GetBucketLocation Action = "GetBucketLocation"
	S3PutBucketPolicy   Action = "PutBucketPolicy"
)

// IAM actions
const (
	IAMListUsers        Action = "ListUsers"
	IAMListRoles        Action = "ListRoles"
	IAMCreateRole       Action = "CreateRole"
	IAMAttachRolePolicy Action = "AttachRolePolicy"
	IAMPutRolePolicy    Action = "PutRolePolicy"
	IAMPassRole         Action = "PassRole"
)

// Lambda actions
const (
	LambdaInvokeFunction     Action = "InvokeFunction"
	LambdaCreateFunction     Action = "CreateFunction"
	LambdaUpdateFunctionCode Action = "UpdateFunctionCode"
	LambdaGetFunction        Action = "GetFunction"
	LambdaListFunctions      Action = "ListFunctions"
)

// DynamoDB actions
const (
	DynamoDBGetItem     Action = "GetItem"
	DynamoDBPutItem     Action = "PutItem"
	DynamoDBUpdateItem  Action = "UpdateItem"
	DynamoDBDeleteItem  Action = "DeleteItem"
	DynamoDBQuery       Action = "Query"
	DynamoDBScan        Action = "Scan"
	DynamoDBCreateTable Action = "CreateTable"
)

// CloudWatch Logs actions
const (
	LogsCreateLogGroup     Action = "CreateLogGroup"
	LogsCreateLogStream    Action = "CreateLogStream"
	LogsPutLogEvents       Action = "PutLogEvents"
	LogsDescribeLogGroups  Action = "DescribeLogGroups"
	LogsDescribeLogStreams Action = "DescribeLogStreams"
	LogsGetLogEvents       Action = "GetLogEvents"
	LogsFilterLogEvents    Action = "FilterLogEvents"
)

// CloudFront actions
const (
	CloudFrontGetDistribution    Action = "GetDistribution"
	CloudFrontCreateInvalidation Action = "CreateInvalidation"
	CloudFrontListDistributions  Action = "ListDistributions"
)

// API Gateway actions (note: many are HTTP verbs)
const (
	APIGatewayGET    Action = "GET"
	APIGatewayPOST   Action = "POST"
	APIGatewayPUT    Action = "PUT"
	APIGatewayDELETE Action = "DELETE"
)

// STS actions
const (
	STSAssumeRole Action = "AssumeRole"
)

// SQS actions
const (
	SQSSendMessage    Action = "SendMessage"
	SQSReceiveMessage Action = "ReceiveMessage"
	SQSDeleteMessage  Action = "DeleteMessage"
	SQSCreateQueue    Action = "CreateQueue"
)

// CloudWatch metrics actions
const (
	CloudWatchListMetrics    Action = "ListMetrics"
	CloudWatchGetMetricData  Action = "GetMetricData"
	CloudWatchPutMetricData  Action = "PutMetricData"
	CloudWatchDescribeAlarms Action = "DescribeAlarms"
)

// Billing & Cost Explorer actions
const (
	BillingViewBilling          Action = "ViewBilling"
	BillingViewUsage            Action = "ViewUsage"
	CostExplorerGetCostAndUsage Action = "GetCostAndUsage"
)

// FullActions returns a list of full action strings (e.g., "ec2:DescribeInstances")
// for the given policies.
//
// @return []string
// @param policies []Policy
// @description A list of AWS policies to convert to full action strings.
func FullActions(policies []Policy) []string {
	out := make([]string, len(policies))

	for i, p := range policies {
		out[i] = string(p.ActionGroup) + ":" + string(p.Action)
	}

	return out
}
