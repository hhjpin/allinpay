package allinpay

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hhjpin/goutils/logger"
	"io/ioutil"
	"net/http"
)

type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Get(req *Request) (*Response, error) {
	if err := c.sign(req); err != nil {
		return nil, err
	}
	body, err := c.doGet(req)
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if err := c.verify(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) verify(req *Request, resp *Response) error {
	m := md5.New()
	m.Write([]byte(resp.SignedValue))
	md5Base64 := base64.StdEncoding.EncodeToString(m.Sum(nil))

	sign, err := base64.StdEncoding.DecodeString(resp.Sign)
	if err != nil {
		logger.Error(err)
		return err
	}

	hash := sha1.New()
	hash.Write([]byte(md5Base64))
	err = rsa.VerifyPKCS1v15(req.Config.GetPublicKey(), crypto.SHA1, hash.Sum(nil), sign)
	if err != nil {
		logger.Error(err)
		return err
	}
	return nil
}

func (c *Client) doGet(req *Request) ([]byte, error) {
	reqBytes, _ := json.Marshal(req.Req)
	uri := fmt.Sprintf("%s?sysid=%s&v=%s&timestamp=%s&req=%s&sign=%s&", req.Config.RequestUrl, req.Sysid, req.V,
		EncodeURIComponent(req.Timestamp), EncodeURIComponent(string(reqBytes)), EncodeURIComponent(req.Sign))
	if req.Config.IsDebug {
		logger.Debug("[allinpay request]:", uri)
	}
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if req.Config.IsDebug {
		logger.Debug("[allinpay response]:", string(body))
	}
	return body, nil
}

func (c *Client) sign(req *Request) error {
	reqBytes, _ := json.Marshal(req.Req)
	sourceStr := req.Sysid + string(reqBytes) + req.Timestamp

	m := md5.New()
	m.Write([]byte(sourceStr))
	md5Base64 := base64.StdEncoding.EncodeToString(m.Sum(nil))

	h := sha1.New()
	h.Write([]byte(md5Base64))
	digest := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(nil, req.Config.GetPrivateKey(), crypto.SHA1, digest)
	if err != nil {
		logger.Error(err)
		return err
	}
	req.Sign = base64.StdEncoding.EncodeToString(sign)

	return nil
}
