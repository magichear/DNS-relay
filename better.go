package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 配置常量
	MaxWorkers         = 1000            // 最大工作协程数
	WorkerQueueSize    = 10000           // 工作队列大小
	CacheSize          = 10000           // 缓存大小
	CacheTTL           = 300             // 缓存TTL（秒）
	ConnectionPoolSize = 50              // 连接池大小
	MaxRetries         = 3               // 最大重试次数
	QueryTimeout       = 5 * time.Second // 查询超时时间
)

// DNS配置映射：域名到IP地址
type Config map[string]string

// 缓存条目
type CacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
}

// 缓存结构（使用分片减少锁竞争）
type DNSCache struct {
	shards   []*CacheShard
	shardNum int
}

type CacheShard struct {
	sync.RWMutex
	entries map[string]*CacheEntry
}

func NewDNSCache(shardNum int) *DNSCache {
	cache := &DNSCache{
		shards:   make([]*CacheShard, shardNum),
		shardNum: shardNum,
	}
	for i := 0; i < shardNum; i++ {
		cache.shards[i] = &CacheShard{
			entries: make(map[string]*CacheEntry),
		}
	}
	return cache
}

func (c *DNSCache) getShard(key string) *CacheShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%uint32(c.shardNum)]
}

func (c *DNSCache) Get(key string) ([]byte, bool) {
	shard := c.getShard(key)
	shard.RLock()
	defer shard.RUnlock()

	entry, exists := shard.entries[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil, false
	}
	return entry.Response, true
}

func (c *DNSCache) Set(key string, response []byte, ttl time.Duration) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	// 简单的LRU淘汰策略
	if len(shard.entries) >= CacheSize/len(c.shards) {
		// 删除一些过期条目
		now := time.Now()
		for k, v := range shard.entries {
			if now.After(v.ExpiresAt) {
				delete(shard.entries, k)
			}
		}
	}

	shard.entries[key] = &CacheEntry{
		Response:  response,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// 连接池
type ConnectionPool struct {
	connections chan *net.UDPConn
	nameserver  *net.UDPAddr
	mu          sync.Mutex
}

func NewConnectionPool(size int, nameserver *net.UDPAddr) *ConnectionPool {
	pool := &ConnectionPool{
		connections: make(chan *net.UDPConn, size),
		nameserver:  nameserver,
	}

	// 预创建连接
	for i := 0; i < size; i++ {
		if conn, err := net.DialUDP("udp", nil, nameserver); err == nil {
			pool.connections <- conn
		}
	}

	return pool
}

func (p *ConnectionPool) Get() *net.UDPConn {
	select {
	case conn := <-p.connections:
		return conn
	default:
		// 如果池中没有连接，创建新连接
		if conn, err := net.DialUDP("udp", nil, p.nameserver); err == nil {
			return conn
		}
		return nil
	}
}

func (p *ConnectionPool) Put(conn *net.UDPConn) {
	if conn == nil {
		return
	}
	select {
	case p.connections <- conn:
	default:
		// 池满了，关闭连接
		conn.Close()
	}
}

// 工作任务
type WorkTask struct {
	Data       []byte
	ClientAddr *net.UDPAddr
}

// Goroutine 池
type WorkerPool struct {
	taskQueue   chan *WorkTask
	workerCount int32
	maxWorkers  int32
	server      *RelayServer
}

func NewWorkerPool(maxWorkers int, server *RelayServer) *WorkerPool {
	return &WorkerPool{
		taskQueue:  make(chan *WorkTask, WorkerQueueSize),
		maxWorkers: int32(maxWorkers),
		server:     server,
	}
}

func (p *WorkerPool) Start() {
	for i := 0; i < int(p.maxWorkers); i++ {
		go p.worker()
		atomic.AddInt32(&p.workerCount, 1)
	}
}

func (p *WorkerPool) worker() {
	defer atomic.AddInt32(&p.workerCount, -1)

	for task := range p.taskQueue {
		p.server.processTask(task)
		// 回收任务对象
		taskPool.Put(task)
	}
}

func (p *WorkerPool) Submit(task *WorkTask) bool {
	select {
	case p.taskQueue <- task:
		return true
	default:
		return false
	}
}

func (p *WorkerPool) Stop() {
	close(p.taskQueue)
}

// 对象池
var (
	messagePool = sync.Pool{
		New: func() interface{} {
			return &Message{}
		},
	}

	queryPool = sync.Pool{
		New: func() interface{} {
			return &QueryPart{}
		},
	}

	taskPool = sync.Pool{
		New: func() interface{} {
			return &WorkTask{}
		},
	}

	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1024)
		},
	}
)

// 事务信息结构体
type Transaction struct {
	DomainName string
	ClientAddr *net.UDPAddr
	StartTime  time.Time
	Context    context.Context
	Cancel     context.CancelFunc
}

// DNS查询部分结构体
type QueryPart struct {
	Name    string
	Type    uint16
	Class   uint16
	Index   int
	rawData []byte
}

func (q *QueryPart) Reset() {
	q.Name = ""
	q.Type = 0
	q.Class = 0
	q.Index = 0
	q.rawData = nil
}

// 解析DNS查询部分
func (q *QueryPart) Unpack(data []byte) {
	q.Reset()
	q.rawData = data

	// 解析域名
	for {
		if q.Index >= len(data) {
			break
		}
		length := int(data[q.Index])
		if length == 0 {
			q.Index++
			break
		}
		q.Index++
		if q.Index+length > len(data) {
			break
		}
		if q.Name != "" {
			q.Name += "."
		}
		q.Name += string(data[q.Index : q.Index+length])
		q.Index += length
	}

	// 解析类型和类别
	if q.Index+4 <= len(data) {
		q.Type = binary.BigEndian.Uint16(data[q.Index : q.Index+2])
		q.Class = binary.BigEndian.Uint16(data[q.Index+2 : q.Index+4])
		q.Index += 4
	}
}

// 打包DNS查询部分
func (q *QueryPart) Pack() []byte {
	var data []byte
	parts := strings.Split(q.Name, ".")

	// 打包域名
	for _, part := range parts {
		if part != "" {
			data = append(data, byte(len(part)))
			data = append(data, []byte(part)...)
		}
	}
	data = append(data, 0x00) // 结束字节

	// 打包类型和类别
	typeBytes := make([]byte, 2)
	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, q.Type)
	binary.BigEndian.PutUint16(classBytes, q.Class)
	data = append(data, typeBytes...)
	data = append(data, classBytes...)

	return data
}

// DNS消息结构体
type Message struct {
	ID         uint16
	Flags      uint16
	Questions  uint16
	Answers    uint16
	Authority  uint16
	Additional uint16
	QR         uint8
	Query      *QueryPart
	RawData    []byte
}

func (m *Message) Reset() {
	m.ID = 0
	m.Flags = 0
	m.Questions = 0
	m.Answers = 0
	m.Authority = 0
	m.Additional = 0
	m.QR = 0
	if m.Query != nil {
		queryPool.Put(m.Query)
		m.Query = nil
	}
	m.RawData = nil
}

// 解析DNS消息
func NewMessage(data []byte) *Message {
	msg := messagePool.Get().(*Message)
	msg.Reset()
	msg.unpack(data)
	return msg
}

func (m *Message) unpack(data []byte) {
	if len(data) < 12 {
		return
	}

	m.RawData = data

	// 解析头部
	m.ID = binary.BigEndian.Uint16(data[0:2])
	m.Flags = binary.BigEndian.Uint16(data[2:4])
	m.Questions = binary.BigEndian.Uint16(data[4:6])
	m.Answers = binary.BigEndian.Uint16(data[6:8])
	m.Authority = binary.BigEndian.Uint16(data[8:10])
	m.Additional = binary.BigEndian.Uint16(data[10:12])

	// 提取QR位
	m.QR = uint8(data[2] >> 7)

	// 如果是查询报文，解析问题部分
	if m.QR == 0 && len(data) > 12 {
		m.Query = queryPool.Get().(*QueryPart)
		m.Query.Unpack(data[12:])
	}
}

// 生成DNS响应报文
func (m *Message) PackResponse(ip string) []byte {
	buffer := bufferPool.Get().([]byte)
	response := buffer[:0] // 重用底层数组

	// 设置响应标志
	var responseFlags uint16
	if ip == "0.0.0.0" {
		responseFlags = 0x8183 // 域名不存在
	} else {
		responseFlags = 0x8180 // 标准查询响应
	}

	// 打包头部
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], m.ID)
	binary.BigEndian.PutUint16(header[2:4], responseFlags)
	binary.BigEndian.PutUint16(header[4:6], m.Questions)
	binary.BigEndian.PutUint16(header[6:8], 1) // 回答数
	binary.BigEndian.PutUint16(header[8:10], m.Authority)
	binary.BigEndian.PutUint16(header[10:12], m.Additional)

	response = append(response, header...)

	// 添加问题部分
	if m.Query != nil {
		response = append(response, m.Query.Pack()...)
	}

	// 添加回答部分
	// 名称指针 (0xC00C)
	response = append(response, 0xC0, 0x0C)
	// 类型 (A记录)
	response = append(response, 0x00, 0x01)
	// 类别 (IN)
	response = append(response, 0x00, 0x01)
	// TTL (666秒)
	ttlBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBytes, 666)
	response = append(response, ttlBytes...)
	// 数据长度 (4字节)
	response = append(response, 0x00, 0x04)

	// IP地址
	ipParts := strings.Split(ip, ".")
	for _, part := range ipParts {
		if val, err := strconv.Atoi(part); err == nil {
			response = append(response, byte(val))
		}
	}

	// 创建结果副本并归还缓冲区
	result := make([]byte, len(response))
	copy(result, response)
	bufferPool.Put(buffer)

	return result
}

// DNS中继服务器结构体
type RelayServer struct {
	config         Config
	conn           *net.UDPConn
	nameserver     *net.UDPAddr
	transaction    map[uint16]Transaction
	mutex          sync.RWMutex
	cache          *DNSCache
	connectionPool *ConnectionPool
	workerPool     *WorkerPool
	stats          struct {
		totalQueries  int64
		cacheHits     int64
		localResolves int64
		relayQueries  int64
		errors        int64
	}
}

// 从配置文件加载配置
func loadConfig(path string) (Config, error) {
	config := make(Config)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			ip := parts[0]
			domain := parts[1]
			config[domain] = ip
		}
	}

	return config, scanner.Err()
}

// 创建新的DNS中继服务器
func NewRelayServer(configPath string) (*RelayServer, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	fmt.Println("Loaded config:", config)

	// 创建UDP连接
	addr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	// 设置上游DNS服务器
	nameserver, err := net.ResolveUDPAddr("udp", "114.114.114.114:53")
	if err != nil {
		return nil, err
	}

	server := &RelayServer{
		config:      config,
		conn:        conn,
		nameserver:  nameserver,
		transaction: make(map[uint16]Transaction),
		cache:       NewDNSCache(256), // 256个分片
	}

	// 创建连接池
	server.connectionPool = NewConnectionPool(ConnectionPoolSize, nameserver)

	// 创建工作池
	server.workerPool = NewWorkerPool(MaxWorkers, server)
	server.workerPool.Start()

	// 启动统计信息输出
	go server.printStats()

	// 启动缓存清理
	go server.cacheCleanup()

	return server, nil
}

// 处理工作任务
func (r *RelayServer) processTask(task *WorkTask) {
	atomic.AddInt64(&r.stats.totalQueries, 1)

	startTime := time.Now()
	msg := NewMessage(task.Data)
	defer messagePool.Put(msg)

	domainName := "unknown"
	handledAs := "unknown"
	flag := false

	if msg.QR == 0 { // 查询报文
		if msg.Query != nil {
			domainName = msg.Query.Name
		}

		// 首先检查缓存
		cacheKey := fmt.Sprintf("%s:%d:%d", domainName, msg.Query.Type, msg.Query.Class)
		if cachedResponse, found := r.cache.Get(cacheKey); found {
			// 更新缓存响应的ID
			if len(cachedResponse) >= 2 {
				binary.BigEndian.PutUint16(cachedResponse[0:2], msg.ID)
			}
			r.conn.WriteToUDP(cachedResponse, task.ClientAddr)
			handledAs = "cache hit"
			atomic.AddInt64(&r.stats.cacheHits, 1)
		} else if ip, exists := r.config[domainName]; exists {
			// 本地配置解析
			response := msg.PackResponse(ip)
			r.conn.WriteToUDP(response, task.ClientAddr)

			// 缓存本地解析结果
			r.cache.Set(cacheKey, response, time.Duration(CacheTTL)*time.Second)

			if ip == "0.0.0.0" {
				handledAs = "intercept"
			} else {
				handledAs = "local resolve"
			}
			atomic.AddInt64(&r.stats.localResolves, 1)
		} else {
			// 转发到上游DNS服务器
			r.forwardQuery(msg, task.ClientAddr, startTime, cacheKey)
			flag = true
			atomic.AddInt64(&r.stats.relayQueries, 1)
		}
	} else if msg.QR == 1 { // 响应报文
		r.handleResponse(msg, task.Data)
		handledAs = "relay response"
	}

	duration := time.Since(startTime)
	if !flag { // 简化输出，第一段中继不打印日志
		fmt.Printf("query to %50s,    handled as %20s,    takes %.4fs\n",
			domainName, handledAs, duration.Seconds())
	}
}

// 转发查询到上游服务器
func (r *RelayServer) forwardQuery(msg *Message, clientAddr *net.UDPAddr, startTime time.Time, cacheKey string) {
	transactionID := msg.ID

	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)

	r.mutex.Lock()
	if _, exists := r.transaction[transactionID]; !exists {
		r.transaction[transactionID] = Transaction{
			DomainName: msg.Query.Name,
			ClientAddr: clientAddr,
			StartTime:  startTime,
			Context:    ctx,
			Cancel:     cancel,
		}
		r.mutex.Unlock()

		// 使用连接池发送查询
		go r.sendUpstreamQuery(msg.RawData, transactionID, cacheKey)
	} else {
		r.mutex.Unlock()
		cancel()
	}
}

// 发送上游查询
func (r *RelayServer) sendUpstreamQuery(data []byte, transactionID uint16, cacheKey string) {
	conn := r.connectionPool.Get()
	if conn == nil {
		atomic.AddInt64(&r.stats.errors, 1)
		return
	}
	defer r.connectionPool.Put(conn)

	// 发送查询
	_, err := conn.Write(data)
	if err != nil {
		atomic.AddInt64(&r.stats.errors, 1)
		return
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(QueryTimeout))

	// 读取响应
	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	n, err := conn.Read(buffer)
	if err != nil {
		atomic.AddInt64(&r.stats.errors, 1)
		return
	}

	// 处理响应
	responseData := make([]byte, n)
	copy(responseData, buffer[:n])

	r.handleUpstreamResponse(responseData, transactionID, cacheKey)
}

// 处理上游响应
func (r *RelayServer) handleUpstreamResponse(data []byte, transactionID uint16, cacheKey string) {
	r.mutex.Lock()
	trans, exists := r.transaction[transactionID]
	if exists {
		delete(r.transaction, transactionID)
	}
	r.mutex.Unlock()

	if !exists {
		return
	}

	trans.Cancel()

	// 发送响应给客户端
	r.conn.WriteToUDP(data, trans.ClientAddr)

	// 缓存响应
	r.cache.Set(cacheKey, data, time.Duration(CacheTTL)*time.Second)

	duration := time.Since(trans.StartTime)
	fmt.Printf("query to %50s,    handled as %20s,    takes %.4fs\n",
		trans.DomainName, "relay", duration.Seconds())
}

// 处理响应报文
func (r *RelayServer) handleResponse(msg *Message, data []byte) {
	transactionID := msg.ID
	r.mutex.Lock()
	trans, exists := r.transaction[transactionID]
	if exists {
		delete(r.transaction, transactionID)
	}
	r.mutex.Unlock()

	if exists {
		trans.Cancel()
		r.conn.WriteToUDP(data, trans.ClientAddr)
	}
}

// 统计信息输出
func (r *RelayServer) printStats() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		total := atomic.LoadInt64(&r.stats.totalQueries)
		cacheHits := atomic.LoadInt64(&r.stats.cacheHits)
		localResolves := atomic.LoadInt64(&r.stats.localResolves)
		relayQueries := atomic.LoadInt64(&r.stats.relayQueries)
		errors := atomic.LoadInt64(&r.stats.errors)

		cacheHitRate := float64(0)
		if total > 0 {
			cacheHitRate = float64(cacheHits) / float64(total) * 100
		}

		fmt.Printf("\n=== DNS Relay Statistics ===\n")
		fmt.Printf("Total Queries: %d\n", total)
		fmt.Printf("Cache Hits: %d (%.1f%%)\n", cacheHits, cacheHitRate)
		fmt.Printf("Local Resolves: %d\n", localResolves)
		fmt.Printf("Relay Queries: %d\n", relayQueries)
		fmt.Printf("Errors: %d\n", errors)
		fmt.Printf("===========================\n\n")
	}
}

// 缓存清理
func (r *RelayServer) cacheCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for _, shard := range r.cache.shards {
			shard.Lock()
			for key, entry := range shard.entries {
				if now.After(entry.ExpiresAt) {
					delete(shard.entries, key)
				}
			}
			shard.Unlock()
		}
	}
}

// 运行DNS中继服务器
func (r *RelayServer) Run() {
	fmt.Printf("High-Performance DNS Relay Server started on port 53\n")
	fmt.Printf("Workers: %d, Cache Shards: %d, Connection Pool: %d\n",
		MaxWorkers, len(r.cache.shards), ConnectionPoolSize)

	buffer := make([]byte, 1024)

	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			atomic.AddInt64(&r.stats.errors, 1)
			continue
		}

		// 从对象池获取任务对象
		task := taskPool.Get().(*WorkTask)
		task.Data = make([]byte, n)
		copy(task.Data, buffer[:n])
		task.ClientAddr = clientAddr

		// 提交任务到工作池
		if !r.workerPool.Submit(task) {
			// 工作队列满了，直接处理
			go func() {
				r.processTask(task)
				taskPool.Put(task)
			}()
		}
	}
}

func main() {
	// 配置文件路径，需要根据实际情况修改
	configPath := "/home/magichaer/CodeBase/test/tmp/example.txt"

	server, err := NewRelayServer(configPath)
	if err != nil {
		fmt.Printf("Failed to create DNS relay server: %v\n", err)
		os.Exit(1)
	}

	server.Run()
}
