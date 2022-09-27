# go-ades
常见对称加密算法 `AES`、`DES`、`3DES` 的Go语言封装

### 安装

```bash
go get github.com/melf-xyzh/go-ades
```

### 使用

#### AES

加密

```go
key := []byte("ABCDEFGHIJKLMNOP")
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
cipher, err := aes.AesEncrypt(src, key, mode, padMode)
if err != nil {
    panic(err)
}
// 转base64
bs64 := base64.StdEncoding.EncodeToString(cipher)
fmt.Println("Go  加密结果:" + bs64)
```

解密

```go
// 转回byte
bt, err := base64.StdEncoding.DecodeString(bs64)
if err != nil {
    fmt.Println("base64转换失败")
}
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
str, err := aes.AesDecrypt(bt, key, mode, padMode)
if err != nil {
    panic(err)
}
```

#### DES

加密

```go
key := []byte("12345678")
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
cipher, err := des.OnceDesEncrypt(src, key, mode, padMode)
if err != nil {
    panic(err)
}
// 转base64
bs64 := base64.StdEncoding.EncodeToString(cipher)
fmt.Println("Go  加密结果:" + bs64)
```

解密

```go
// 转回byte
bt, err := base64.StdEncoding.DecodeString(bs64)
if err != nil {
    fmt.Println("base64转换失败")
}
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
str, err := des.OnceDesDecrypt(bt, key, mode, padMode)
if err != nil {
    panic(err)
}
```

#### 3DES

加密

```go
key := []byte("123456781234567812345678")
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
cipher, err := des.TripleDesEncrypt(src, key, mode, padMode)
if err != nil {
    panic(err)
}
// 转base64
bs64 := base64.StdEncoding.EncodeToString(cipher)
fmt.Println("Go  加密结果:" + bs64)
```

解密

```go
// 转回byte
bt, err := base64.StdEncoding.DecodeString(bs64)
if err != nil {
    fmt.Println("base64转换失败")
}
// mode（加密模式）：CBC/ECB/CTR/OFB/CFB
// padMode（填充模式）：PKCS5/PKCS7
str, err := des.TripleDesDecrypt(bt, key, mode, padMode)
if err != nil {
    panic(err)
}
```

