/**
 * @Time    :2022/9/27 13:47
 * @Author  :Xiaoyu.Zhang
 */

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/melf-xyzh/go-ades/constant"
	"github.com/melf-xyzh/go-ades/padding"
	"io"
)

// AesEncrypt
/**
 *  @Description:
 *  @param data
 *  @param key
 *  @param desType
 *  @param mode
 *  @param padMode
 *  @return out
 *  @return err
 */
func AesEncrypt(data, key []byte, mode adesconst.EncryptMode, padMode adesconst.PaddingMode) (out []byte, err error) {
	// NewCipher创建一个新的加密块
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}
	// 获取加密区块大小
	bs := block.BlockSize()
	// 补全码
	switch padMode {
	case adesconst.NoPadding:
		// 不填充
	case adesconst.PKCS1:
		err = errors.New("暂未实现")
		return
	case adesconst.PKCS5:
		// 获取填充原文（pkcs5填充）
		data = padding.PKCS5Padding(data, bs)
	case adesconst.PKCS7:
		// 获取填充原文（pkcs7填充）
		data = padding.PKCS7Padding(data, bs)
	case adesconst.ZeroPadding:
		data = padding.ZeroPadding(data, bs)
	default:
		err = errors.New("未知的填充算法")
		return
	}
	if len(data)%bs != 0 {
		err = errors.New("data is not a multiple of the block size")
		return
	}
	out = make([]byte, len(data))

	iv := make([]byte, bs, bs)
	// 在非ECB情况下，需要生成IV
	if mode != adesconst.ECB {
		out = make([]byte, bs+len(data))
		iv = out[:bs]
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return
		}
	}
	// 根据不同的模式进行加密解密
	switch mode {
	case adesconst.CBC: // 密码分组链接模式
		blockMode := cipher.NewCBCEncrypter(block, iv)
		blockMode.CryptBlocks(out[bs:], data)
	case adesconst.ECB: // 电码本模式
		dst := out
		for len(data) > 0 {
			//Encrypt加密第一个块，将其结果保存到dst
			block.Encrypt(dst, data[:bs])
			data = data[bs:]
			dst = dst[bs:]
		}
	case adesconst.CTR: // 计算器模式
		blockMode := cipher.NewCTR(block, iv)
		blockMode.XORKeyStream(out[bs:], data)
	case adesconst.OFB: // 输出反馈模式
		blockMode := cipher.NewOFB(block, iv)
		blockMode.XORKeyStream(out[bs:], data)
	case adesconst.CFB: // 密码反馈模式
		blockMode := cipher.NewCFBDecrypter(block, iv)
		blockMode.XORKeyStream(out[bs:], data)
	default:
		err = errors.New("加密模式不合法")
	}
	return
}

// AesDecrypt
/**
 *  @Description:
 *  @param data
 *  @param key
 *  @param desType
 *  @param mode
 *  @param padMode
 *  @return out
 *  @return err
 */
func AesDecrypt(data, key []byte, mode adesconst.EncryptMode, padMode adesconst.PaddingMode) (out []byte, err error) {
	// NewCipher创建一个新的加密块
	var block cipher.Block
	block, err = aes.NewCipher(key)
	if err != nil {
		return
	}
	// 获取加密区块大小
	bs := block.BlockSize()
	if len(data) < bs {
		err = errors.New("data too short")
		return
	}

	iv := make([]byte, bs, bs)
	// 在非ECB情况下，需要生成IV
	if mode != adesconst.ECB {
		iv = data[:bs]
		data = data[bs:]
	}

	if len(data)%bs != 0 {
		err = errors.New("密文长度不合法")
		return
	}
	out = make([]byte, len(data))

	// 根据不同的模式进行加密解密
	switch mode {
	case adesconst.CBC: // 密码分组链接模式
		blockMode := cipher.NewCBCDecrypter(block, iv)
		blockMode.CryptBlocks(out, data)
	case adesconst.ECB: // 电码本模式
		dst := out
		for len(data) > 0 {
			//Encrypt解密第一个块，将其结果保存到dst
			block.Decrypt(dst, data[:bs])
			data = data[bs:]
			dst = dst[bs:]
		}
	case adesconst.CTR: // 计算器模式
		blockMode := cipher.NewCTR(block, iv)
		blockMode.XORKeyStream(out, data)
	case adesconst.OFB: // 输出反馈模式
		blockMode := cipher.NewOFB(block, iv)
		blockMode.XORKeyStream(out, data)
	case adesconst.CFB: // 密码反馈模式
		blockMode := cipher.NewCFBEncrypter(block, iv)
		blockMode.XORKeyStream(out, data)
	default:
		err = errors.New("加密模式不合法")
	}
	// 反填
	switch padMode {
	case adesconst.NoPadding:
		// 不填充
	case adesconst.PKCS1:
		err = errors.New("暂未实现")
		return
	case adesconst.PKCS5:
		// pkcs5填充
		out = padding.PKCS5UnPadding(out)
	case adesconst.PKCS7:
		// pkcs5填充
		out = padding.PKCS7UnPadding(out)
	case adesconst.ZeroPadding:
		// Zero填充
		out = padding.ZeroUnPadding(out)
	default:
		err = errors.New("未知的填充算法")
		return
	}
	return
}
