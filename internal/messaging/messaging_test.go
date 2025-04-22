package messaging

//func TestRetrieveObjectFromCredentialOffer(t *testing.T) {
//	offer := entity.Offering{
//		CredentialOffer: "openid-credential-offer://credential_offer=%7B%22credential_issuer%22%3A%20%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credentials%22%3A%20%5B%22UniversityDegree_LDP%22%5D%2C%22grants%22%3A%20%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%20%7B%22pre-authorized_code%22%3A%20%22adhjhdjajkdkhjhdj%22%2C%22user_pin_required%22%3A%20false%7D%7D%7D",
//		Request: common.Request{
//			TenantId: "test",
//		},
//	}
//
//	want := &credential.CredentialOfferParameters{
//		CredentialIssuer: "https://credential-issuer.example.com",
//		Credentials:      []string{"UniversityDegree_LDP"},
//		Grants: credential.Grants{
//			AuthorizationCode: credential.AuthorizationCode{IssuerState: ""},
//			PreAuthorizedCode: credential.PreAuthorizedCode{
//				PreAuthorizationCode: "adhjhdjajkdkhjhdj",
//				UserPinRequired:      false,
//			},
//		},
//	}
//
//	got, err := getCredentialOfferObject(offer)
//	if err != nil {
//		t.Errorf("unexpected error occured: %v", err)
//	}
//
//	require.True(t, cmp.Equal(got.Grants, want.Grants, cmpopts.EquateEmpty()))
//}

//func TestRetrieveObjectFromCredentialOfferUri(t *testing.T) {
//	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		if r.Method != http.MethodGet {
//			t.Errorf("wrong http method! got: %s, want: %s", r.Method, http.MethodGet)
//		}
//
//		if r.URL.String() != "/credential-offer.jwt" {
//			t.Errorf("call to wrong url! got: %s, want: %s", r.URL.String(), "/credential-offer.jwt")
//		}
//
//		response := `{
//			"credential_issuer": "https://credential-issuer.example.com",
//			"credentials": [
//				"UniversityDegree_LDP"
//			],
//			"grants": {
//				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
//					"pre-authorized_code": "adhjhdjajkdkhjhdj",
//					"user_pin_required": false
//			}}}`
//
//		_, err := w.Write([]byte(response))
//		if err != nil {
//			t.Fatalf("unexpected error while responding: %v", err)
//		}
//	}))
//	defer server.Close()
//
//	offer := entity.Offering{
//		CredentialOfferUri: "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(server.URL) + "%2Fcredential-offer.jwt",
//		Request: common.Request{
//			TenantId: "test",
//		},
//	}
//
//	want := &credential.CredentialOfferParameters{
//		CredentialIssuer: "https://credential-issuer.example.com",
//		Credentials:      []string{"UniversityDegree_LDP"},
//		Grants: credential.Grants{
//			AuthorizationCode: credential.AuthorizationCode{IssuerState: ""},
//			PreAuthorizedCode: credential.PreAuthorizedCode{
//				PreAuthorizationCode: "adhjhdjajkdkhjhdj",
//				UserPinRequired:      false,
//			},
//		},
//	}
//
//	got, err := getCredentialOfferObject(offer)
//	if err != nil {
//		t.Errorf("unexpected error occured: %v", err)
//	}
//
//	require.True(t, cmp.Equal(got.Grants, want.Grants, cmpopts.EquateEmpty()))
//}
