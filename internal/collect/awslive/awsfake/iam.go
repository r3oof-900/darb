package awsfake

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// The fake account's credentials (item 4): one user, deploy, with one
// active key; the root has none.

// The credential report: the root (no key) and deploy (one active key).
const credentialReport = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active," +
	"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service," +
	"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service," +
	"cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\n" +
	"<root_account>,arn:aws:iam::111122223333:root,2026-01-01T00:00:00+00:00,not_supported,N/A,N/A,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n" +
	"deploy,arn:aws:iam::111122223333:user/deploy,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2026-02-01T00:00:00+00:00," +
	"2026-11-01T00:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n"

func (f *fake) GenerateCredentialReport(ctx context.Context, _ *iam.GenerateCredentialReportInput, _ ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	if err := f.do(ctx, "GenerateCredentialReport", ""); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if *f.pending > 0 {
		*f.pending--
		return &iam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeStarted}, nil
	}
	return &iam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeComplete}, nil
}

func (f *fake) GetCredentialReport(ctx context.Context, _ *iam.GetCredentialReportInput, _ ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if err := f.do(ctx, "GetCredentialReport", ""); err != nil {
		return nil, err
	}
	generated := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	return &iam.GetCredentialReportOutput{Content: []byte(credentialReport), ReportFormat: iamtypes.ReportFormatTypeTextCsv, GeneratedTime: &generated}, nil
}

func (f *fake) ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if err := f.do(ctx, "ListAccessKeys", aws.ToString(in.UserName)); err != nil {
		return nil, err
	}
	created := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{{
		UserName: in.UserName, AccessKeyId: aws.String("AKIAEXAMPLEDEPLOY001"), Status: iamtypes.StatusTypeActive, CreateDate: &created,
	}}}, nil
}

func (f *fake) GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if err := f.do(ctx, "GetAccessKeyLastUsed", aws.ToString(in.AccessKeyId)); err != nil {
		return nil, err
	}
	used := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return &iam.GetAccessKeyLastUsedOutput{UserName: aws.String("deploy"), AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{LastUsedDate: &used}}, nil
}
