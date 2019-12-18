# allinpay

通联支付 golang 基础包

# Usage

获取`golang`包

```sh
go get -u github.com/hhjpin/allinpay
```

使用例子

```go
pay, err := allinpay.New(&allinpay.Config{
    RequestUrl:  os.Getenv("AllinpayRequestUrl"),
    PrivateFile: os.Getenv("AllinpayPrivateFile"),
    PublicFile:  os.Getenv("AllinpayPublicFile"),
    Sysid:       os.Getenv("AllinpaySysid"),
})
if err != nil {
    panic(err)
}
resp, err := pay.Request("MemberService", "createMember", map[string]interface{}{
    "bizUserId":  "test_user_1",
    "memberType": 3,
    "source":     1,
})
if err != nil {
    panic(err)
}
fmt.Println(resp)
fmt.Println(resp.CheckStatus())

resp, err = pay.RequestAndCheckStatus("MemberService", "createMember", map[string]interface{}{
    "bizUserId":  "test_user_1",
    "memberType": 3,
    "source":     1,
})
fmt.Println(resp, err)
```

## License

MIT