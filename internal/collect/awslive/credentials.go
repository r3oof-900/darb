package awslive

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
)

// credentials reads the users' credentials (item 4): the credential report
// first (state, dates, password, MFA), ListAccessKeys for every user (the
// key IDs and creation dates), and GetAccessKeyLastUsed for each key only
// when the report could not be read. A failed call is recorded and is a
// coverage gap; it never stops the collection.
func (a *account) credentials(ctx context.Context, c *Clients, users []awsraw.UserDetail) {
	report := a.credentialReport(ctx, c)
	keys := a.accessKeys(ctx, c, users)
	lastUsed := map[string]string{}
	if report == nil {
		lastUsed = a.keysLastUsed(ctx, c, keys)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acct.CredentialReport = report
	if len(keys) > 0 {
		a.acct.AccessKeys = keys
	}
	if len(lastUsed) > 0 {
		a.acct.KeyLastUsed = lastUsed
	}
}

// accessKeys: every user's keys (ListAccessKeys); a user whose call failed
// is left out (its keys come from the report, or are unknown).
func (a *account) accessKeys(ctx context.Context, c *Clients, users []awsraw.UserDetail) map[string][]awsraw.AccessKeyMetadata {
	keys := map[string][]awsraw.AccessKeyMetadata{}
	for i := range users {
		name := users[i].UserName
		var list []awsraw.AccessKeyMetadata
		err := a.call(ctx, "iam", "", "ListAccessKeys", name, func(ctx context.Context) error {
			p := iam.NewListAccessKeysPaginator(c.IAM, &iam.ListAccessKeysInput{UserName: aws.String(name)})
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					return err
				}
				for k := range page.AccessKeyMetadata {
					list = append(list, keyMetadata(&page.AccessKeyMetadata[k]))
				}
			}
			return nil
		})
		if err == nil {
			keys[name] = list
		}
	}
	return keys
}

// keysLastUsed: each key's last use (GetAccessKeyLastUsed), only when the
// report, which has it, could not be read.
func (a *account) keysLastUsed(ctx context.Context, c *Clients, keys map[string][]awsraw.AccessKeyMetadata) map[string]string {
	lastUsed := map[string]string{}
	for _, list := range keys {
		for _, k := range list {
			_ = a.call(ctx, "iam", "", "GetAccessKeyLastUsed", k.AccessKeyID, func(ctx context.Context) error {
				out, err := c.IAM.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(k.AccessKeyID)})
				if err == nil && out.AccessKeyLastUsed != nil && out.AccessKeyLastUsed.LastUsedDate != nil {
					lastUsed[k.AccessKeyID] = out.AccessKeyLastUsed.LastUsedDate.UTC().Format(time.RFC3339)
				}
				return err
			})
		}
	}
	return lastUsed
}

func keyMetadata(k *iamtypes.AccessKeyMetadata) awsraw.AccessKeyMetadata {
	m := awsraw.AccessKeyMetadata{UserName: aws.ToString(k.UserName), AccessKeyID: aws.ToString(k.AccessKeyId), Status: string(k.Status)}
	if k.CreateDate != nil {
		m.CreateDate = k.CreateDate.UTC().Format(time.RFC3339)
	}
	return m
}

// credentialReport asks IAM to prepare the report and reads it once it is
// ready, polling with a doubling wait (1s, 2s, 4s, at most 8s) up to
// ReportWait; nil when it could not be read.
func (a *account) credentialReport(ctx context.Context, c *Clients) *awsraw.CredentialReport {
	wait, waited := time.Second, time.Duration(0)
	for {
		var state iamtypes.ReportStateType
		err := a.call(ctx, "iam", "", "GenerateCredentialReport", "", func(ctx context.Context) error {
			out, err := c.IAM.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
			if err == nil {
				state = out.State
			}
			return err
		})
		if err != nil {
			return nil
		}
		if state == iamtypes.ReportStateTypeComplete {
			break
		}
		if waited >= a.o.ReportWait {
			a.record("iam", "", "GetCredentialReport", "", awsraw.StatusTimeout,
				fmt.Sprintf("the credential report was not ready within %s", a.o.ReportWait))
			return nil
		}
		if a.o.Sleep(ctx, wait) != nil {
			return nil
		}
		waited += wait
		wait = min(2*wait, 8*time.Second)
	}
	var report *awsraw.CredentialReport
	_ = a.call(ctx, "iam", "", "GetCredentialReport", "", func(ctx context.Context) error {
		out, err := c.IAM.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
		if err != nil {
			return err
		}
		generated := ""
		if out.GeneratedTime != nil {
			generated = out.GeneratedTime.UTC().Format(time.RFC3339)
		}
		report, err = awsraw.ParseCredentialReport(out.Content, generated)
		return err
	})
	return report
}

// sleep waits d or until ctx is done.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// record adds a call outcome that no single API call returned (the report
// still not ready when the wait ends).
func (a *account) record(service, region, api, target, status, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acct.Calls = append(a.acct.Calls, awsraw.Call{Service: service, Region: region, API: api, Target: target, Status: status, Error: detail})
}
