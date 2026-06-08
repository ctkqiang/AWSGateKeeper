// Package aws provides an S3-backed audit logger that persists audit
// events as newline-delimited JSON files in a configurable S3 bucket.
//
// Key layout:
//
//	{prefix}/YYYY/MM/DD/{uuid}.json        — single event
//	{prefix}/YYYY/MM/DD/{timestamp}_batch_{uuid}.jsonl  — batch
//
// Environment variables required at construction time:
//
//	AUDIT_S3_BUCKET  MANDATORY  target S3 bucket name
//	AUDIT_S3_PREFIX  optional   key prefix (defaults to "audit-logs")
//	AWS_REGION       optional   fallback region    (defaults to "us-east-1")
package aws

import (
	"aws_gatekeeper/internal/model"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// S3AuditLogger writes audit events to S3 as individual JSON objects.
//
// Each call to WriteAuditEvent produces a single .json file; batch writes
// produce a single .jsonl file.  Files are organised by date under the
// configured key prefix so that S3 lifecycle policies can efficiently
// expire, transition, or archive old audit data.
type S3AuditLogger struct {
	client *s3.Client      // pre-configured S3 client
	bucket string          // destination S3 bucket name
	prefix string          // key prefix for all uploaded objects
	ctx    context.Context // context passed to every S3 API call
}

// NewS3AuditLogger reads configuration from environment variables, builds
// an AWS SDK config, and returns a ready-to-use S3AuditLogger.
//
//	@return  initialised logger suitable for WriteAuditEvent and
//	         WriteBatchAuditEvents
//	@return  non-nil if AUDIT_S3_BUCKET is empty or the AWS config cannot
//	         be loaded
func NewS3AuditLogger() (*S3AuditLogger, error) {
	bucket := os.Getenv("AUDIT_S3_BUCKET")
	if bucket == "" {
		return nil, fmt.Errorf("AUDIT_S3_BUCKET must be set")
	}

	prefix := os.Getenv("AUDIT_S3_PREFIX")
	if prefix == "" {
		prefix = "audit-logs"
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}

	ctx := context.TODO()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	return &S3AuditLogger{
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
		prefix: prefix,
		ctx:    ctx,
	}, nil
}

// WriteAuditEvent marshals a single AuditEvent to JSON and uploads it as
// an S3 object.  If Timestamp is zero, it is set to time.Now().UTC().
//
// Object key: {prefix}/YYYY/MM/DD/{uuid}.json
//
//	@param  event  the audit record to persist
//	@return        nil on success; non-nil if marshalling or the S3 PUT
//	               operation fails
func (l *S3AuditLogger) WriteAuditEvent(event model.AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	key := path.Join(
		l.prefix,
		event.Timestamp.Format("2006/01/02"),
		uuid.New().String()+".json",
	)

	_, err = l.client.PutObject(l.ctx, &s3.PutObjectInput{
		Bucket: aws_sdk.String(l.bucket),
		Key:    aws_sdk.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("upload audit event to S3: %w", err)
	}
	return nil
}

// WriteBatchAuditEvents marshals a slice of AuditEvent values into a
// newline-delimited JSON (.jsonl) buffer and uploads it as a single S3
// object.  Timestamps are left as-is (callers should set them beforehand).
//
// An empty slice is a no-op and returns nil immediately.
//
// Object key: {prefix}/YYYY/MM/DD/{timestamp}_batch_{uuid}.jsonl
//
//	@param  events  audit records to persist in a single batch
//	@return         nil on success; non-nil if any marshalling step or
//	                the S3 PUT fails
func (l *S3AuditLogger) WriteBatchAuditEvents(events []model.AuditEvent) error {
	var buf bytes.Buffer

	if len(events) == 0 {
		return nil
	}

	for _, ev := range events {
		data, err := json.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal event: %w", err)
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	now := time.Now().UTC()
	key := path.Join(
		l.prefix,
		now.Format("2006/01/02"),
		now.Format("20060102_150405")+"_batch_"+uuid.New().String()+".jsonl",
	)

	_, err := l.client.PutObject(l.ctx, &s3.PutObjectInput{
		Bucket: aws_sdk.String(l.bucket),
		Key:    aws_sdk.String(key),
		Body:   bytes.NewReader(buf.Bytes()),
	})
	if err != nil {
		return fmt.Errorf("upload batch to S3: %w", err)
	}

	return nil
}
