package allinpay

import (
	"fmt"
)

type Response struct {
	Status      string `json:"status"`
	Sign        string `json:"sign"`
	ErrorCode   string `json:"errorCode"`   //仅当 status=error 时有效
	Message     string `json:"message"`     //仅当 status=error 时有效
	SignedValue string `json:"signedValue"` //JSON, 仅当 status=OK 时有效
}

func (r *Response) CheckStatus() error {
	if r.Status != "OK" {
		return fmt.Errorf("%s(%s)", r.Message, r.ErrorCode)
	}
	return nil
}
