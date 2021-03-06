package integration_test

import (
	"testing"

	"encoding/json"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestIntrospectToken(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runIntrospectTokenTest(t, strategy)
	}
}

func runIntrospectTokenTest(t *testing.T, strategy oauth2.AccessTokenStrategy) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	a, err := oauthClient.Token(goauth.NoContext)
	require.Nil(t, err)
	b, err := oauthClient.Token(goauth.NoContext)
	require.Nil(t, err)

	for _, c := range []struct {
		prepare  func(*gorequest.SuperAgent) *gorequest.SuperAgent
		isActive bool
		scopes   string
	}{
		{
			prepare: func(s *gorequest.SuperAgent) *gorequest.SuperAgent {
				return s.SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret)
			},
			isActive: true,
			scopes:   "",
		},
		{
			prepare: func(s *gorequest.SuperAgent) *gorequest.SuperAgent {
				return s.Set("Authorization", "bearer " + a.AccessToken)
			},
			isActive: true,
			scopes:   "fosite",
		},
		{
			prepare: func(s *gorequest.SuperAgent) *gorequest.SuperAgent {
				return s.Set("Authorization", "bearer " + a.AccessToken)
			},
			isActive: true,
			scopes:   "",
		},
		{
			prepare: func(s *gorequest.SuperAgent) *gorequest.SuperAgent {
				return s.Set("Authorization", "bearer " + a.AccessToken)
			},
			isActive: false,
			scopes:   "foo",
		},
		{
			prepare: func(s *gorequest.SuperAgent) *gorequest.SuperAgent {
				return s.Set("Authorization", "bearer " + b.AccessToken)
			},
			isActive: false,
			scopes:   "",
		},
	} {
		res := struct {
			Active bool `json:"active"`
		}{}
		s := gorequest.New()
		s = s.Post(ts.URL + "/introspect").
			Type("form").
			SendStruct(map[string]string{"token": b.AccessToken, "scope": c.scopes})
		_, bytes, errs := c.prepare(s).End()

		assert.Nil(t, json.Unmarshal([]byte(bytes), &res))
		t.Logf("Got answer: %s", bytes)
		assert.Len(t, errs, 0)
		assert.Equal(t, c.isActive, res.Active)
	}
}
