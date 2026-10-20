package commands

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSTS records each AssumeRoleWithSAML call and rejects any DurationSeconds
// above maxDuration the way STS does.
type stubSTS struct {
	stsiface.STSAPI
	maxDuration int64
	err         error
	calls       []*sts.AssumeRoleWithSAMLInput
}

func (s *stubSTS) AssumeRoleWithSAML(in *sts.AssumeRoleWithSAMLInput) (*sts.AssumeRoleWithSAMLOutput, error) {
	s.calls = append(s.calls, in)
	if s.err != nil {
		return nil, s.err
	}
	if in.DurationSeconds != nil && *in.DurationSeconds > s.maxDuration {
		return nil, awserr.New("ValidationError",
			"The requested DurationSeconds exceeds the MaxSessionDuration set for this role.", nil)
	}
	return &sts.AssumeRoleWithSAMLOutput{}, nil
}

func samlInput(duration int64) *sts.AssumeRoleWithSAMLInput {
	return &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String("arn:aws:iam::123456789012:saml-provider/idp"),
		RoleArn:         aws.String("arn:aws:iam::123456789012:role/dev"),
		SAMLAssertion:   aws.String("assertion"),
		DurationSeconds: aws.Int64(duration),
	}
}

func TestAssumeRoleWithSAMLRetriesWithoutDurationAboveMax(t *testing.T) {
	svc := &stubSTS{maxDuration: 3600}

	_, err := assumeRoleWithSAML(svc, samlInput(43200))

	require.NoError(t, err)
	require.Len(t, svc.calls, 2)
	assert.Equal(t, int64(43200), aws.Int64Value(svc.calls[0].DurationSeconds))
	assert.Nil(t, svc.calls[1].DurationSeconds)
	assert.Equal(t, "arn:aws:iam::123456789012:role/dev", aws.StringValue(svc.calls[1].RoleArn))
}

func TestAssumeRoleWithSAMLNoRetryWithinMax(t *testing.T) {
	svc := &stubSTS{maxDuration: 43200}

	_, err := assumeRoleWithSAML(svc, samlInput(3600))

	require.NoError(t, err)
	require.Len(t, svc.calls, 1)
}

func TestAssumeRoleWithSAMLNoRetryOnOtherErrors(t *testing.T) {
	svc := &stubSTS{err: awserr.New("AccessDenied", "Not authorized to perform sts:AssumeRoleWithSAML", nil)}

	_, err := assumeRoleWithSAML(svc, samlInput(43200))

	require.Error(t, err)
	assert.Len(t, svc.calls, 1)
}
