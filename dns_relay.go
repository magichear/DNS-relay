package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNS配置映射：域名到IP地址
type Config map[string]string

// 事务信息结构体
type Transaction struct {
	DomainName string
	ClientAddr *net.UDPAddr
	StartTime  time.Time
}

// DNS查询部分结构体
type QueryPart struct {
	Name    string
	Type    uint16
	Class   uint16
	Index   int
	rawData []byte
}

// 解析DNS查询部分
func (q *QueryPart) Unpack(data []byte) {
	q.Name = ""
	q.Index = 0
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

// 解析DNS消息
func NewMessage(data []byte) *Message {
	msg := &Message{RawData: data}
	msg.unpack(data)
	return msg
}

func (m *Message) unpack(data []byte) {
	if len(data) < 12 {
		return
	}

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
		m.Query = &QueryPart{}
		m.Query.Unpack(data[12:])
	}
}

// 生成DNS响应报文
func (m *Message) PackResponse(ip string) []byte {
	var response []byte

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

	return response
}

// DNS中继服务器结构体
type RelayServer struct {
	config      Config
	conn        *net.UDPConn
	nameserver  *net.UDPAddr
	transaction map[uint16]Transaction
	mutex       sync.RWMutex
}

// 从配置文件加载配置
func loadConfig(path string) (Config, error) {
	config := make(Config)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

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

	fmt.Println(config)

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

	return &RelayServer{
		config:      config,
		conn:        conn,
		nameserver:  nameserver,
		transaction: make(map[uint16]Transaction),
	}, nil
}

// 处理DNS消息
func (r *RelayServer) process(data []byte, clientAddr *net.UDPAddr) {
	startTime := time.Now()
	msg := NewMessage(data)
	domainName := "unknown"
	handledAs := "unknown"
	flag := false

	if msg.QR == 0 { // 查询报文
		if msg.Query != nil {
			domainName = msg.Query.Name
		}

		// 检查本地配置
		if ip, exists := r.config[domainName]; exists {
			response := msg.PackResponse(ip)
			_, err := r.conn.WriteToUDP(response, clientAddr)
			if err != nil {
				return
			}
			if ip == "0.0.0.0" {
				handledAs = "intercept"
			} else {
				handledAs = "local resolve"
			}
		} else {
			// 转发到上游DNS服务器
			transactionID := msg.ID
			r.mutex.Lock()
			if _, exists := r.transaction[transactionID]; !exists {
				r.transaction[transactionID] = Transaction{
					DomainName: domainName,
					ClientAddr: clientAddr,
					StartTime:  startTime,
				}
				_, err := r.conn.WriteToUDP(data, r.nameserver)
				if err != nil {
					return
				}
			}
			r.mutex.Unlock()
			flag = true
		}
	} else if msg.QR == 1 { // 响应报文
		transactionID := msg.ID
		r.mutex.Lock()
		if trans, exists := r.transaction[transactionID]; exists {
			delete(r.transaction, transactionID)
			r.mutex.Unlock()
			domainName = trans.DomainName
			startTime = trans.StartTime
			_, err := r.conn.WriteToUDP(data, trans.ClientAddr)
			if err != nil {
				return
			}
			handledAs = "relay"
		} else {
			r.mutex.Unlock()
			handledAs = "[ERROR] unknown transaction id"
		}
	}

	duration := time.Since(startTime)
	if !flag { // 简化输出，第一段中继不打印日志
		fmt.Printf("query to %50s,    handled as %20s,    takes %.4fs\n",
			domainName, handledAs, duration.Seconds())
	}
}

// 运行DNS中继服务器
func (r *RelayServer) Run() {
	fmt.Println("DNS Relay Server started on port 53")
	buffer := make([]byte, 1024)

	for {
		n, clientAddr, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		// 为每个请求创建goroutine处理
		go r.process(buffer[:n], clientAddr)
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
