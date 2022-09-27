/**
 * @Time    :2022/9/27 13:52
 * @Author  :Xiaoyu.Zhang
 */

package adesconst

type DesType int
type EncryptMode int
type PaddingMode int

const (
	CBC EncryptMode = iota // 密码分组链接模式
	ECB                    // 电码本模式
	CTR                    // 计算器模式
	OFB                    // 输出反馈模式
	CFB                    // 密码反馈模式
)

const (
	NoPadding   PaddingMode = iota // 不填充
	PKCS1                          // PKCS1填充
	PKCS5                          // PKCS5填充
	PKCS7                          // PKCS7填充
	ZeroPadding                    // Zero填充
)

const (
	Des       DesType = 1 // DES
	TripleDes DesType = 3 // 3DES
)
