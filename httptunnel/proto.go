package httptunnel

type pushPayload struct {
	ID           string `faker:"uuid_hyphenated" json:"id"`
	CreateTime   string `faker:"date" json:"create_time"`
	ResourceType string `faker:"word" json:"resource_type"`
	EventType    string `faker:"word" json:"event_type"`
	Summary      string `faker:"sentence" json:"summary"`
	OriginalType string `faker:"word" json:"original_type"`
	Ciphertext   string `faker:"-" json:"ciphertext"`
}

type pullParam struct {
	Mchid         int32  `json:"mchid"`
	TransactionID string `faker:"uuid_digit" json:"transaction_id"`
}

type pullResp struct {
	Appid         string `faker:"uuid_hyphenated" json:"appid"`
	Mchid         string `json:"mchid"`
	OutTradeNO    string `faker:"uuid_digit" json:"out_trade_no"`
	Openid        string `faker:"uuid_hyphenated" json:"openid"`
	TransactionID string `faker:"uuid_hyphenated" json:"transaction_id"`
	Ciphertext    string `faker:"-" json:"ciphertext"`
}
