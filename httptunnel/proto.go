package httptunnel

type pushPayload struct {
	AccountID   string `faker:"uuid_hyphenated" json:"account_id"`
	AccessToken string `faker:"jwt" json:"access_token"`
	Payload     string `faker:"-" json:"payload"`
}

type pullParam struct {
	AccountID     string `faker:"uuid_hyphenated" json:"account_id"`
	TransactionID string `faker:"uuid_hyphenated" json:"transaction_id"`
	AccessToken   string `faker:"jwt" json:"access_token"`
}

type pullResp struct {
	AccountID     string `faker:"uuid_hyphenated" json:"account_id"`
	TransactionID string `faker:"uuid_hyphenated" json:"transaction_id"`
	Payload       string `faker:"-" json:"payload"`
}
