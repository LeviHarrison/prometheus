// Copyright 2023 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/prometheus/prometheus/config"
)

type azureADRoundTripper struct {
	credential azureADCredential
	token      azcore.AccessToken
	next       http.RoundTripper
}

type azureADCredential interface {
	GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)
}

func newAzureADRoundTripper(cfg *config.AzureADConfig, next http.RoundTripper) (http.RoundTripper, error) {
	if next == nil {
		next = http.DefaultTransport
	}

	var cred azureADCredential
	var err error

	switch cfg.AuthenticationMethod {
	case config.ADAuthMethodOAuth:
		cred, err = azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, string(cfg.ClientSecret), nil)
	case config.ADAuthMethodManagedIdentity:
		cred, err = azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
			ID: azidentity.ClientID(cfg.ClientID),
		})
	}
	if err != nil {
		return nil, fmt.Errorf("error creating Azure AD OAuth client: %w", err)
	}

	return &azureADRoundTripper{
		credential: cred,
		next:       next,
	}, nil
}

func (rt *azureADRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.token.ExpiresOn.Before(time.Now()) || rt.token.ExpiresOn.Equal(time.Now()) {
		var err error
		rt.token, err = rt.credential.GetToken(req.Context(), policy.TokenRequestOptions{})
		if err != nil {
			return nil, fmt.Errorf("error fetching Azure AD token: %w", err)
		}
	}

	req.Header.Set("Authorization", rt.token.Token)

	return rt.next.RoundTrip(req)
}
