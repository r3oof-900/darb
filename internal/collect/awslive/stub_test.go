package awslive

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/r3oof-900/darb/internal/collect/awsraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// The SDK factory's real clients (serializers, deserializers, paginators,
// retries) against a transport that answers every request in memory: no
// request leaves the process (the endpoint is .invalid and the transport
// never dials).

type stubResponse struct {
	status int
	body   string
}

type stubTransport struct {
	mu   sync.Mutex
	seen []string
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	op := s.operation(req, string(body))
	s.mu.Lock()
	s.seen = append(s.seen, op)
	s.mu.Unlock()
	r, ok := stubResponses()[op]
	if !ok {
		r = stubResponse{500, `{"__type":"InternalFailure","message":"stub: no response for ` + op + `"}`}
	}
	return &http.Response{
		StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body)), Request: req,
		Header: http.Header{"Content-Type": []string{"application/xml"}, "X-Amzn-Requestid": []string{"stub"}},
	}, nil
}

// operation names a request by its protocol: the JSON protocols' target
// header, the query protocols' Action, or S3's sub-resource.
func (s *stubTransport) operation(req *http.Request, body string) string {
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		return t
	}
	if form, err := url.ParseQuery(body); err == nil && form.Get("Action") != "" {
		return form.Get("Action") + "/" + form.Get("Marker")
	}
	if strings.HasPrefix(req.URL.Path, "/clusters") {
		return "eks " + req.URL.Path
	}
	bucket, _, _ := strings.Cut(req.URL.Host, ".")
	for _, sub := range []string{"policy", "encryption", "publicAccessBlock", "tagging", "location"} {
		if req.URL.Query().Has(sub) {
			return "s3 " + bucket + " " + sub
		}
	}
	return "s3 ListBuckets"
}

func stubResponses() map[string]stubResponse {
	ok := func(body string) stubResponse { return stubResponse{200, body} }
	return map[string]stubResponse{
		"GetCallerIdentity/": ok(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>` +
			`<Arn>arn:aws:sts::111122223333:assumed-role/audit/darb</Arn><UserId>AROA:darb</UserId><Account>111122223333</Account>` +
			`</GetCallerIdentityResult></GetCallerIdentityResponse>`),
		"GenerateCredentialReport/": ok(`<GenerateCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GenerateCredentialReportResult>` +
			`<State>COMPLETE</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>`),
		// The report's Content is a base64 CSV: a header and the root's row.
		"GetCredentialReport/": ok(`<GetCredentialReportResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetCredentialReportResult>` +
			`<Content>dXNlcixhcm4sYWNjZXNzX2tleV8xX2FjdGl2ZQo8cm9vdF9hY2NvdW50Pixhcm46YXdzOmlhbTo6MTExMTIyMjIzMzMzOnJvb3QsZmFsc2UK</Content>` +
			`<ReportFormat>text/csv</ReportFormat><GeneratedTime>2026-11-27T12:00:00Z</GeneratedTime>` +
			`</GetCredentialReportResult></GetCredentialReportResponse>`),
		"GetAccountAuthorizationDetails/": ok(`<GetAccountAuthorizationDetailsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetAccountAuthorizationDetailsResult>` +
			`<IsTruncated>true</IsTruncated><Marker>p2</Marker><RoleDetailList><member><RoleName>app</RoleName>` +
			`<Arn>arn:aws:iam::111122223333:role/app</Arn><AssumeRolePolicyDocument>%7B%22Version%22%3A%222012-10-17%22%7D</AssumeRolePolicyDocument>` +
			`</member></RoleDetailList></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>`),
		"GetAccountAuthorizationDetails/p2": ok(`<GetAccountAuthorizationDetailsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetAccountAuthorizationDetailsResult>` +
			`<IsTruncated>false</IsTruncated><RoleDetailList><member><RoleName>admin</RoleName><Arn>arn:aws:iam::111122223333:role/admin</Arn>` +
			`</member></RoleDetailList></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>`),
		"s3 ListBuckets": ok(`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>pii</Name>` +
			`<BucketRegion>eu-west-1</BucketRegion></Bucket></Buckets></ListAllMyBucketsResult>`),
		"s3 pii policy":     {404, `<Error><Code>NoSuchBucketPolicy</Code><Message>The bucket policy does not exist</Message></Error>`},
		"s3 pii encryption": {403, `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`},
		"s3 pii publicAccessBlock": ok(`<PublicAccessBlockConfiguration><RestrictPublicBuckets>true</RestrictPublicBuckets>` +
			`</PublicAccessBlockConfiguration>`),
		"s3 pii tagging":               ok(`<Tagging><TagSet><Tag><Key>data-classification</Key><Value>pii</Value></Tag></TagSet></Tagging>`),
		"TrentService.ListAliases":     ok(`{"Aliases":[],"Truncated":false}`),
		"TrentService.ListKeys":        {400, `{"__type":"ThrottlingException","message":"Rate exceeded"}`},
		"eks /clusters":                ok(`{"clusters":[]}`),
		"secretsmanager.ListSecrets":   {400, `{"__type":"AccessDeniedException","Message":"not authorized"}`},
		"AmazonSSM.DescribeParameters": ok(`{"Parameters":[]}`),
	}
}

type noBackoff struct{}

func (noBackoff) BackoffDelay(int, error) (time.Duration, error) { return 0, nil }

func TestSDKClientsAgainstStubs(t *testing.T) {
	tr := &stubTransport{}
	cfg := aws.Config{
		Region:       "eu-west-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDSTUBSTUBSTUBSTUB", "stub-secret", ""),
		HTTPClient:   &http.Client{Transport: tr},
		BaseEndpoint: aws.String("https://aws.stub.invalid"),
		Retryer: func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(func(o *retry.StandardOptions) { o.Backoff = noBackoff{} }), 2)
		},
	}
	rec := &coverage.Recorder{}
	snap, err := Collect(context.Background(), &Options{Factory: NewFactory(&cfg), Regions: []string{"eu-west-1"}}, rec)
	if err != nil {
		t.Fatal(err)
	}
	a := snap.Accounts[0]
	if a.ID != "111122223333" || len(a.Auth.RoleDetailList) != 2 {
		t.Fatalf("account %q, roles %d (both IAM pages)", a.ID, len(a.Auth.RoleDetailList))
	}
	b := a.Buckets[0]
	if b.Policy != "" || b.PolicyFailed || b.Encryption != nil || !b.PublicAccessBlock.RestrictPublicBuckets || b.Tags[0].Value != "pii" {
		t.Fatalf("bucket %+v", b)
	}
	status := map[string]string{}
	for _, c := range a.Calls {
		status[c.API+" "+c.Target] = c.Status
	}
	want := map[string]string{
		"GetBucketPolicy pii": awsraw.StatusOK, "GetBucketEncryption pii": awsraw.StatusAccessDenied,
		"ListKeys ": awsraw.StatusThrottling, "ListSecrets ": awsraw.StatusAccessDenied, "ListClusters ": awsraw.StatusOK,
	}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s: %q, want %q", k, status[k], v)
		}
	}
	if rec.Count(coverage.KindThrottled) != 1 || rec.Count(coverage.KindAccessDenied) != 2 || rec.Len() != 3 {
		t.Fatalf("gaps %+v", rec.Gaps())
	}
	throttled := 0
	for _, op := range tr.seen {
		if op == "TrentService.ListKeys" {
			throttled++
		}
	}
	if throttled != 2 {
		t.Fatalf("ListKeys attempts: %d (the throttled call is retried)", throttled)
	}
}
