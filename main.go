package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Tunnel struct {
	Remote string `json:"remote"`
	Local  string `json:"local"`
	Open   bool   `json:"open"`
	Name   string `json:"name"`
}

type SSHTunnel struct {
	sshClient    *ssh.Client
	Addr         string `json:"addr"`          //地址端口 199.199.199.199:22
	User         string `json:"user"`          //用户 root
	Pass         string `json:"pass"`          //密码 root 免密登录可不配置
	IdentityFile string `json:"identity_file"` //认证证书
	Name         string `json:"name"`
	Tunnels      []Tunnel
	BufferSise   int64
	Timeout      time.Duration
	isValid      bool
	Open         bool `json:"open"` //是否开启
}

func (st *SSHTunnel) Close() {
	if nil != st.sshClient {
		st.sshClient.Close()
	}
}

func (st *SSHTunnel) GetSSHClient() (*ssh.Client, error) {
	if st.sshClient != nil {
		return st.sshClient, nil
	}
	if !st.isValid {
		return nil, errors.New("valid connect")
	}
	var auth []ssh.AuthMethod
	auth = make([]ssh.AuthMethod, 0)
	if len(st.Pass) > 0 {
		auth = append(auth, ssh.Password(st.Pass))
	}

	if len(st.IdentityFile) > 0 {
		key, err := ioutil.ReadFile(st.IdentityFile)
		if err != nil {
			return nil, err
		}
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}

	//ssh.PublicKeys()
	sc := &ssh.ClientConfig{
		User: st.User,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: st.Timeout * time.Millisecond,
	}
	var err error
	st.sshClient, err = ssh.Dial("tcp", st.Addr, sc)
	if err != nil {
		return nil, err
	}
	return st.sshClient, err
}

func (st *SSHTunnel) ClientClose() {
	if st.sshClient != nil {
		st.sshClient.Close()
		st.sshClient = nil
	}
}

func (st *SSHTunnel) connect(t Tunnel) {
	if !t.Open {
		log.Printf(`主机[%s]隧道[%s]：%s <=> %s 未开启`, st.Name, t.Name, t.Local, t.Remote)
		return
	}
	ll, err := net.Listen("tcp", t.Local)
	if err != nil {
		log.Printf(`开启主机[%s]隧道[%s]本地端口监听失败: %s, %s`, st.Name, t.Name, t.Local, err)
		return
	}
	defer func() {
		ll.Close()
		log.Printf(`断开主机[%s]隧道[%s]连接：%s <=> %s`, st.Name, t.Name, t.Local, t.Remote)
	}()
	log.Printf(`开启主机[%s]隧道[%s]：%s <=> %s`, st.Name, t.Name, t.Local, t.Remote)

	for {
		lc, err := ll.Accept()
		if err != nil {
			log.Printf(`主机[%s]隧道[%s]接受来自本地的连接失败: %s`, st.Name, t.Name, err)
			return
		}
		log.Printf(`主机[%s]隧道[%s]接收到本地连接 => %s`, st.Name, t.Name, t.Local)
		sc, err := st.GetSSHClient()
		if err != nil {
			log.Printf(`主机[%s]连接失败: %s`, st.Name, err)
			lc.Close()
			continue
		}
		rc, err := sc.Dial("tcp", t.Remote)
		if err != nil {
			log.Printf(`主机[%s]隧道[%s]连接失败: %s`, st.Name, t.Name, err)
			st.ClientClose()
			lc.Close()
			continue
		}
		log.Printf(`主机[%s]隧道[%s]连接成功 => %s `, st.Name, t.Name, t.Remote)
		st.transfer(lc, rc, t)
	}
}

//链接ssh
func (st *SSHTunnel) initSSHClient() {
	if len(st.Pass) == 0 && len(st.IdentityFile) == 0 {
		st.isValid = false
	} else {
		st.isValid = true
	}
	if !st.isValid {
		log.Printf("主机[%s(%s)]配置无效，连接取消", st.Name, st.Addr)
		return
	}
	if st.BufferSise == 0 {
		st.BufferSise = 5 * 1024
	}
	if st.Timeout == 0 {
		st.Timeout = 3000
	}
	log.Printf("开始连接主机[%s(%s)]...", st.Name, st.Addr)
	_, err := st.GetSSHClient()
	if nil != err {
		errormsg := err.Error()
		st.isValid = false
		log.Printf(`主机[%s(%s)]连接失败: %s`, st.Name, st.Addr, errormsg)
	} else {
		log.Printf("主机[%s(%s)]连接成功", st.Name, st.Addr)
		st.isValid = true
	}
}

//数据交换
func (st SSHTunnel) transfer(lc net.Conn, rc net.Conn, t Tunnel) {
	copyBufPool := sync.Pool{
		New: func() interface{} {
			b := make([]byte, st.BufferSise)
			return &b
		},
	}
	go func() {
		defer lc.Close()
		defer rc.Close()
		//从远程拷贝到本地
		log.Printf("[下行]开始转发主机[%s]隧道[%s] %s <=> %s:数据", st.Name, t.Name, t.Local, t.Remote)
		bufp := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufp)
		io.CopyBuffer(lc, rc, *bufp)
		log.Printf("[下行]转发完成主机[%s]隧道[%s] %s <=> %s:数据", st.Name, t.Name, t.Local, t.Remote)
	}()
	go func() {
		defer rc.Close()
		defer lc.Close()
		//从本地拷贝到远程
		log.Printf("[上行]开始转发主机[%s]隧道[%s] %s <=> %s:数据", st.Name, t.Name, t.Remote, t.Local)
		bufp := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufp)
		io.CopyBuffer(rc, lc, *bufp)
		log.Printf("[上行]转发完成主机[%s]隧道[%s] %s <=> %s:数据", st.Name, t.Name, t.Remote, t.Local)
	}()
}

var (
	confing = flag.String("c","/etc/sshtunnel/config.json","配置文件位置")
)

func main() {
	flag.Parse()
	var sts []SSHTunnel
	var p = *confing
	log.Printf("使用配置文件 %s", p)
	f, err := ioutil.ReadFile(p)
	if err != nil {
		log.Printf(`载入配置文件出错: %s`, err)
		os.Exit(-1)
	}
	err = json.Unmarshal(f, &sts)
	if nil != err {
		log.Printf(`解析配置文件内容出错: %s`, err)
		os.Exit(-1)
	}

	var wg sync.WaitGroup
	for _, st := range sts {
		if st.Open {
			st.initSSHClient()
			if st.isValid {
				wg.Add(1)
				go func() {
					start(st)
					wg.Done()
				}()
				log.Printf(`启动主机[%s(%s)]隧道配置`, st.Name, st.Addr)
			}
		} else {
			log.Printf("[%s(%s)没有开启SSH连接，跳过]", st.Name, st.Addr)
		}

	}
	wg.Wait()
}

func start(st SSHTunnel) {
	defer st.Close()
	var wg sync.WaitGroup
	for _, t := range st.Tunnels {
		wg.Add(1)
		go func(tunnel Tunnel) {
			st.connect(tunnel)
			wg.Done()
		}(t)
	}
	wg.Wait()
}
