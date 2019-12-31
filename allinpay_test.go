package allinpay

import (
	"io/ioutil"
	"os"
	"testing"
)

func NewPay() *Pay {
	privateFile := os.Getenv("AllinpayPrivateFile")
	priFile, err := os.Open(privateFile)
	if err != nil {
		panic(err)
	}
	defer priFile.Close()
	privateData, err := ioutil.ReadAll(priFile)
	if err != nil {
		panic(err)
	}
	publicFile := os.Getenv("AllinpayPublicFile")
	pubFile, err := os.Open(publicFile)
	if err != nil {
		panic(err)
	}
	defer priFile.Close()
	publicData, err := ioutil.ReadAll(pubFile)
	if err != nil {
		panic(err)
	}

	pay, err := New(&Config{
		RequestUrl:  os.Getenv("AllinpayRequestUrl"),
		PrivateData: privateData,
		PublicData:  publicData,
		Sysid:       os.Getenv("AllinpaySysid"),
		IsDebug:     true,
	})
	if err != nil {
		panic(err)
	}
	return pay
}

func TestPay_Request(t *testing.T) {
	pay := NewPay()
	resp, err := pay.Request("MemberService", "createMember", map[string]interface{}{
		"bizUserId":  "test_user_1",
		"memberType": 3,
		"source":     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp)
	t.Log(resp.CheckStatus())

	resp, err = pay.RequestAndCheckStatus("MemberService", "createMember", map[string]interface{}{
		"bizUserId":  "test_user_1",
		"memberType": 3,
		"source":     1,
	})
	t.Log(resp, err)
}

func TestMemberServiceSetRealName(t *testing.T) {
	pay := NewPay()
	no, err := pay.GetConfig().Encrypt([]byte("111111111111111111"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pay.RequestAndCheckStatus("MemberService", "setRealName", map[string]interface{}{
		"bizUserId":    "test_user_1",
		"isAuth":       true,
		"name":         "小李",
		"identityType": 1,
		"identityNo":   string(no),
	})
	t.Log(resp, err)
}
