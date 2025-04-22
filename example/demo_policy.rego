package demo

import future.keywords.if

default accept_credentials := false

accept_credentials if {
	input.tenant_id == "foo"
	input.credential_issuer == "hydra"
	input.grants.authorization_code.issuer_state == "eyJhbGciOiJSU0EtFYUaBy"
	input.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"] == "AOIPO235"
	input.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].user_pin_required == false
}
