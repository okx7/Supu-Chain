// Copyright 2019 The go-ethereum Authors
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

package legacypool

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
)

// nonceEntry存储nonce值及其过期时间
// nonce实体存储结构，包含nonce值和过期时间
type nonceEntry struct {
	nonce    uint64    // nonce值
	expireAt time.Time // 过期时间
}

// noncer是一个小型虚拟状态数据库，用于管理交易池中账户的可执行nonce
// 如果某个账户未知，则会回退到从真实状态数据库中读取
type noncer struct {
	fallback  *state.StateDB                       // 回退的状态数据库
	nonces    map[common.Address]nonceEntry        // 带过期时间的nonce映射
	lock      sync.Mutex                           // 保护nonces的互斥锁
	ttl       time.Duration                        // nonce缓存的生存时间
	cleanTick *time.Ticker                         // 定期清理的计时器
	quit      chan struct{}                        // 停止清理协程的信号
}

// newNoncer创建一个新的虚拟状态数据库来跟踪池中的nonce
// 默认TTL为1小时，清理间隔为5分钟
func newNoncer(statedb *state.StateDB) *noncer {
	// 默认1小时过期时间
	return newNoncerWithTTL(statedb, 1*time.Hour, 5*time.Minute)
}

// newNoncerWithTTL创建一个带有指定TTL和清理间隔的noncer
func newNoncerWithTTL(statedb *state.StateDB, ttl, cleanInterval time.Duration) *noncer {
	n := &noncer{
		fallback:  statedb.Copy(),
		nonces:    make(map[common.Address]nonceEntry),
		ttl:       ttl,
		cleanTick: time.NewTicker(cleanInterval),
		quit:      make(chan struct{}),
	}
	// 启动清理协程
	go n.cleanLoop()
	return n
}

// cleanLoop在后台定期清理过期的nonce
func (txn *noncer) cleanLoop() {
	for {
		select {
		case <-txn.cleanTick.C:
			txn.cleanExpired()
		case <-txn.quit:
			txn.cleanTick.Stop()
			return
		}
	}
}

// cleanExpired清理所有过期的nonce条目
func (txn *noncer) cleanExpired() {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	now := time.Now()
	// 遍历所有地址和nonce条目，删除过期的
	for addr, entry := range txn.nonces {
		if now.After(entry.expireAt) {
			delete(txn.nonces, addr)
			log.Debug("Removed expired nonce from cache", "address", addr, "nonce", entry.nonce)
		}
	}
}

// Stop停止noncer的后台清理工作
func (txn *noncer) Stop() {
	close(txn.quit)
}

// get返回账户的当前nonce，如果账户未知，则回退到真实的状态数据库
func (txn *noncer) get(addr common.Address) uint64 {
	// 我们对get操作使用互斥锁，因为底层状态
	// 即使是只读访问也会改变数据库
	txn.lock.Lock()
	defer txn.lock.Unlock()

	now := time.Now()
	// 检查是否存在该地址的nonce条目且未过期
	if entry, ok := txn.nonces[addr]; ok {
		if now.Before(entry.expireAt) {
			return entry.nonce
		}
		// 如果已过期，则删除它
		delete(txn.nonces, addr)
	}

	// 从回退状态中获取nonce
	if nonce := txn.fallback.GetNonce(addr); nonce != 0 {
		txn.nonces[addr] = nonceEntry{
			nonce:    nonce,
			expireAt: now.Add(txn.ttl),
		}
		return nonce
	}
	return 0
}

// set插入一个新的虚拟nonce到虚拟状态数据库中
// 以便当池请求时返回，而不是访问真实的状态数据库
func (txn *noncer) set(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.nonces[addr] = nonceEntry{
		nonce:    nonce,
		expireAt: time.Now().Add(txn.ttl),
	}
}

// setIfLower更新虚拟状态数据库中的虚拟nonce，前提是新的nonce更小
func (txn *noncer) setIfLower(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	now := time.Now()
	current := uint64(0)
	
	// 检查是否存在该地址的nonce条目且未过期
	if entry, ok := txn.nonces[addr]; ok {
		if now.Before(entry.expireAt) {
			current = entry.nonce
		} else {
			// 如果已过期，则删除它
			delete(txn.nonces, addr)
		}
	}
	
	// 如果没有找到有效的nonce，则从回退状态中获取
	if current == 0 {
		if nonce := txn.fallback.GetNonce(addr); nonce != 0 {
			current = nonce
			txn.nonces[addr] = nonceEntry{
				nonce:    current,
				expireAt: now.Add(txn.ttl),
			}
		}
	}
	
	if current <= nonce {
		return
	}
	
	txn.nonces[addr] = nonceEntry{
		nonce:    nonce,
		expireAt: now.Add(txn.ttl),
	}
}

// setAll设置所有账户的nonce为给定的映射
func (txn *noncer) setAll(all map[common.Address]uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	now := time.Now()
	expireTime := now.Add(txn.ttl)
	
	// 清空当前nonces
	txn.nonces = make(map[common.Address]nonceEntry, len(all))
	
	// 使用新值和过期时间填充
	for addr, nonce := range all {
		txn.nonces[addr] = nonceEntry{
			nonce:    nonce,
			expireAt: expireTime,
		}
	}
}
