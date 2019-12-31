package allinpay

import (
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

func (c *Client) doGet(req *Request) ([]byte, error) {
	reqBytes, _ := json.Marshal(req.Req)
	uri := fmt.Sprintf("%s?sysid=%s&v=%s&timestamp=%s&req=%s&sign=%s&", req.Config.RequestUrl, req.Sysid, req.V,
		EncodeURIComponent(req.Timestamp), EncodeURIComponent(string(reqBytes)), EncodeURIComponent(req.Sign))
	if req.Config.IsDebug {
		logger.Info("[allinpay request]:", uri)
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
		logger.Info("[allinpay response]:", string(body))
	}
	return body, nil
}

func (c *Client) sign(req *Request) error {
	reqBytes, _ := json.Marshal(req.Req)
	sourceStr := req.Sysid + string(reqBytes) + req.Timestamp

	var err error
	req.Sign, err = req.Config.Sign([]byte(sourceStr))
	return err
}

func (c *Client) verify(req *Request, resp *Response) error {
	return req.Config.Verify(resp.SignedValue, resp.Sign)
}
