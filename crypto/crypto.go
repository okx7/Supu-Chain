// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
const DigestLength = 32

var (
	secp256k1N     = S256().Params().N
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))

	keccakState256Cache = fastcache.New(100 * 1024 * 1024)
)

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

var keccakState256Pool = sync.Pool{
	New: func() interface{} {
		return sha3.NewLegacyKeccak256().(KeccakState)
	}}

// EllipticCurve contains curve operations.
type EllipticCurve interface {
	elliptic.Curve

	// Point marshaling/unmarshaing.
	Marshal(x, y *big.Int) []byte
	Unmarshal(data []byte) (x, y *big.Int)
}

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak256().(KeccakState)
}

// HashData hashes the provided data using the KeccakState and returns a 32 byte hash
func HashData(kh KeccakState, data []byte) (h common.Hash) {
	if hash, ok := keccakState256Cache.HasGet(nil, data); ok {
		return common.BytesToHash(hash)
	}
	kh.Reset()
	kh.Write(data)
	kh.Read(h[:])
	keccakState256Cache.Set(data, h.Bytes())
	return h
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	if len(data) == 1 {
		if hash, ok := keccakState256Cache.HasGet(nil, data[0]); ok {
			return hash
		}
	}
	b := make([]byte, 32)
	d := keccakState256Pool.Get().(KeccakState)
	defer keccakState256Pool.Put(d)
	d.Reset()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	if len(data) == 1 {
		keccakState256Cache.Set(data[0], b)
	}
	return b
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	if len(data) == 1 {
		if hash, ok := keccakState256Cache.HasGet(nil, data[0]); ok {
			return common.BytesToHash(hash)
		}
	}
	d := keccakState256Pool.Get().(KeccakState)
	defer keccakState256Pool.Put(d)
	d.Reset()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	if len(data) == 1 {
		keccakState256Cache.Set(data[0], h.Bytes())
	}
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// CreateAddress2 creates an ethereum address given the address bytes, initial
// contract code hash and a salt.
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak256([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := toECDSA(d, false)
	return priv
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = S256().ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// UnmarshalPubkey converts bytes to a secp256k1 public key.
func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := S256().Unmarshal(pub)
	if x == nil {
		return nil, errInvalidPubkey
	}
	if !S256().IsOnCurve(x, y) {
		return nil, errInvalidPubkey
	}
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return S256().Marshal(pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if byteErr, ok := err.(hex.InvalidByteError); ok {
		return nil, fmt.Errorf("invalid hex character %q in private key", byte(byteErr))
	} else if err != nil {
		return nil, errors.New("invalid hex data for private key")
	}
	return ToECDSA(b)
}

// KeyBackupConfig 密钥备份配置
type KeyBackupConfig struct {
	BackupLocations []string // 备份位置
	BackupEnabled   bool     // 是否启用备份
	RetryCount      int      // 失败重试次数
}

// 默认配置
var DefaultKeyBackupConfig = KeyBackupConfig{
	BackupLocations: []string{"./keybackup", "./keybackup_alt"},
	BackupEnabled:   true,
	RetryCount:      3,
}

// 全局配置实例
var GlobalKeyBackupConfig = DefaultKeyBackupConfig

// SecureKeyOperation 安全地执行密钥操作，包含异常处理与重试逻辑
func SecureKeyOperation(operation func() error) error {
	var lastError error
	
	// 尝试多次执行操作
	for i := 0; i <= GlobalKeyBackupConfig.RetryCount; i++ {
		err := operation()
		if err == nil {
			return nil
		}
		lastError = err
		
		// 记录日志但继续尝试
		log.Error("密钥操作失败", "错误", err, "尝试次数", i+1)
		
		// 最后一次尝试失败后不再等待
		if i < GlobalKeyBackupConfig.RetryCount {
			time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
		}
	}
	
	return fmt.Errorf("密钥操作在%d次尝试后失败: %v", GlobalKeyBackupConfig.RetryCount+1, lastError)
}

// SaveECDSAWithBackup 保存密钥并创建备份
func SaveECDSAWithBackup(file string, key *ecdsa.PrivateKey) error {
	// 先保存主文件
	if err := SaveECDSA(file, key); err != nil {
		return err
	}
	
	// 如果备份功能已禁用，直接返回
	if !GlobalKeyBackupConfig.BackupEnabled {
		return nil
	}
	
	// 创建备份
	for _, backupDir := range GlobalKeyBackupConfig.BackupLocations {
		// 确保备份目录存在
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			log.Error("创建备份目录失败", "目录", backupDir, "错误", err)
			continue
		}
		
		// 构建备份文件路径
		_, fileName := filepath.Split(file)
		backupFile := filepath.Join(backupDir, fileName)
		
		// 通过安全操作函数保存备份
		backupErr := SecureKeyOperation(func() error {
			return SaveECDSA(backupFile, key)
		})
		
		if backupErr != nil {
			log.Error("创建密钥备份失败", "位置", backupFile, "错误", backupErr)
			// 继续尝试其他备份位置
		}
	}
	
	return nil
}

// LoadECDSAWithRecovery 尝试加载密钥，如果主文件损坏则从备份恢复
func LoadECDSAWithRecovery(file string) (*ecdsa.PrivateKey, error) {
	// 尝试从主文件加载
	key, err := LoadECDSA(file)
	if err == nil {
		return key, nil
	}
	
	// 记录主文件加载失败
	log.Error("主密钥文件加载失败", "文件", file, "错误", err)
	
	// 如果备份功能已禁用，直接返回错误
	if !GlobalKeyBackupConfig.BackupEnabled {
		return nil, err
	}
	
	// 尝试从备份恢复
	_, fileName := filepath.Split(file)
	for _, backupDir := range GlobalKeyBackupConfig.BackupLocations {
		backupFile := filepath.Join(backupDir, fileName)
		
		// 检查备份文件是否存在
		if _, statErr := os.Stat(backupFile); statErr != nil {
			continue
		}
		
		// 尝试加载备份
		key, backupErr := LoadECDSA(backupFile)
		if backupErr == nil {
			log.Info("已从备份恢复密钥", "备份位置", backupFile)
			
			// 恢复主文件
			if restoreErr := SaveECDSA(file, key); restoreErr != nil {
				log.Error("恢复主密钥文件失败", "错误", restoreErr)
			}
			
			return key, nil
		}
		
		log.Error("备份密钥加载失败", "备份", backupFile, "错误", backupErr)
	}
	
	return nil, fmt.Errorf("无法加载密钥，所有备份尝试均失败，原始错误: %v", err)
}

// LoadECDSA loads a secp256k1 private key from the given file.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 64)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("invalid key size: %d", n)
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	return HexToECDSA(string(buf))
}

// readASCII reads into 'buf', stopping when the buffer is full or
// when a non-printable control character is encountered.
func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

// checkKeyFileEnd skips over additional newlines at the end of a key file.
func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0600)
}

// GenerateKey generates a new private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	clear(bytes)
}
