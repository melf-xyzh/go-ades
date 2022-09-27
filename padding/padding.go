/**
 * @Time    :2022/9/22 14:15
 * @Author  :Xiaoyu.Zhang
 */

package padding

import (
	"bytes"
)

// 参考文档
// https://blog.csdn.net/shyrainxy/article/details/112974055
// https://blog.csdn.net/hai046/article/details/52353934
// https://my.oschina.net/andyhua/blog/5338403
// https://blog.csdn.net/s1095622320/article/details/125404922

// PKCS5Padding
/**
 *  @Description: pkcs5补码算法（将数据填充到8的倍数）
 *  @param ciphertext 密文
 *  @param blockSize 区块大小
 *  @return []byte
 */
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

// PKCS5UnPadding
/**
 *  @Description: pkcs5减码算法
 *  @param origData
 *  @return []byte
 */
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unPadding 次
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// ZeroPadding
/**
 *  @Description: 数据长度不对齐时使用0填充，否则不填充。
 *  @param ciphertext
 *  @param blockSize
 *  @return []byte
 */
func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padText...)
}

// ZeroUnPadding
/**
 *  @Description: Zero反填充
 *  @param origData
 *  @return []byte
 */
func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unPadding 次
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

// PKCS7Padding
/**
 *  @Description: pkcs7补码算法
 *  @param ciphertext 密文
 *  @param blockSize 区块大小
 *  @return []byte
 */
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

// PKCS7UnPadding
/**
 *  @Description: pkcs7减码算法
 *  @param plantText
 *  @return []byte
 */
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unPadding := int(plantText[length-1])
	return plantText[:(length - unPadding)]
}
