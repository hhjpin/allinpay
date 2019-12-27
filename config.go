package allinpay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hhjpin/goutils/logger"
	"io/ioutil"
	"os"
)

type Config struct {
	RequestUrl  string //请求地址
	PrivateFile string //私钥文件
	PublicFile  string //公钥文件
	Sysid       string //系统id

	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey

	IsDebug bool
}

func (c *Config) init() error {
	if err := c.initPrivateKey(); err != nil {
		return err
	}
	if err := c.initPublicKey(); err != nil {
		return err
	}
	return nil
}

func (c *Config) initPrivateKey() error {
	if c.PrivateFile == "" {
		return fmt.Errorf("私钥文件必须指定")
	}
	priFile, err := os.Open(c.PrivateFile)
	if err != nil {
		logger.Error(err)
		return err
	}
	defer func() {
		_ = priFile.Close()
	}()
	privateData, err := ioutil.ReadAll(priFile)
	if err != nil {
		logger.Error(err)
		return err
	}

	block, _ := pem.Decode(privateData)
	if block == nil {
		logger.Error("sign pem.Decode error")
		return fmt.Errorf("sign pem.Decode error")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		logger.Error(err)
		return err
	}
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		err = fmt.Errorf("key is not a valid RSA public key")
		logger.Error(err)
		return err
	}

	c.privateKey = key
	return nil
}

func (c *Config) initPublicKey() error {
	if c.PublicFile == "" {
		return fmt.Errorf("公钥文件必须指定")
	}

	pubFile, err := os.Open(c.PublicFile)
	if err != nil {
		logger.Error(err)
		return err
	}
	defer func() {
		_ = pubFile.Close()
	}()
	publicData, err := ioutil.ReadAll(pubFile)
	if err != nil {
		logger.Error(err)
		return err
	}

	block, _ := pem.Decode(publicData)
	if block == nil {
		logger.Error("verify pem.Decode error")
		return fmt.Errorf("verify pem.Decode error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error(err)
		return err
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("key is not a valid RSA public key")
		logger.Error(err)
		return err
	}

	c.publicKey = key
	return nil
}

func (c *Config) GetPrivateKey() *rsa.PrivateKey {
	return c.privateKey
}

func (c *Config) GetPublicKey() *rsa.PublicKey {
	return c.publicKey
}
