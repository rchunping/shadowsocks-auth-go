package main

import "os"
import "io"
import "net"
import "log"
import "sync"
import "flag"
import "encoding/json"

var LISTEN string
var SERVER string
var USERS []string

func handleConnection(c net.Conn) {

	// rfc1929: username/password

	var ver byte // 0x05 ?
	var ml, nl, pl int
	var support, allow bool
	var s net.Conn
	var err error
	var wg sync.WaitGroup

	buf := make([]byte, 1500)

	defer c.Close()

	// rfc1928
	if _, err := io.ReadFull(c, buf[0:2]); err != nil {
		goto cerr
	}
	ver = buf[0]
	ml = int(buf[1])
	if _, err := io.ReadFull(c, buf[0:ml]); err != nil {
		goto cerr
	}

	// client support username/password auth ?
	support = false
	for ml >= 0 {
		if buf[ml] == 0x02 {
			support = true
			break
		}
		ml = ml - 1
	}

	if support == false {
		log.Println("client not support rfc1929.")
		c.Write([]byte{ver, 0xff})
		return
	}

	c.Write([]byte{ver, 0x02})

	// rfc1929 start

	// wait user/passww
	if _, err := io.ReadFull(c, buf[0:2]); err != nil {
		goto cerr
	}

	nl = int(buf[1])
	if _, err := io.ReadFull(c, buf[0:nl]); err != nil {
		goto cerr
	}

	if _, err := io.ReadFull(c, buf[nl:nl+1]); err != nil {
		goto cerr
	}

	pl = int(buf[nl])

	if _, err := io.ReadFull(c, buf[nl+1:nl+pl+1]); err != nil {
		goto cerr
	}

	buf[nl] = ':'

	// buf[ username : password ]
	//               ^(nl)    ^(nl+pl+1)

	allow = false

	for _, up := range USERS {

		if up == string(buf[0:nl+pl+1]) {
			allow = true
			break
		}
	}

	if allow {
		c.Write([]byte{ver, 0x00}) // success
	} else {
		c.Write([]byte{ver, 0x01}) // failed
	}

	// connect to server
	s, err = net.Dial("tcp", SERVER)
	if err != nil {
		// handle error
		log.Println("connect to server failed.")
		return
	}
	defer s.Close()

	s.Write([]byte{ver, 0x01, 0x00}) // no auth

	if _, err := io.ReadFull(s, buf[0:2]); err != nil {
		log.Println("server connection error.")
		return
	}

	if buf[1] != 0x00 {
		log.Println("server need auth.")

		// tell client auth failed here?
		return
	}

	// loop read/write
	wg.Add(1)
	go func() {
		io.Copy(c, s)
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		io.Copy(s, c)
		wg.Done()
	}()

	wg.Wait()
	return

cerr:
	log.Println("client connection error.")
	return

}

func main() {

	var pconf_file = flag.String("c", "auth.json", "config file format:json")

	flag.Parse()

	//log.Printf("%#v",*pconf_file)

	if cf, err := os.Open(*pconf_file); err != nil {
		log.Fatal("config read failed.")
	} else {
		defer cf.Close()

		buf := make([]byte, 4096)
		n, _ := cf.Read(buf)

		//log.Printf("%s",buf[0:n])
		var v map[string]interface{}
		if err := json.Unmarshal(buf[0:n], &v); err != nil {
			log.Fatal("config parse failed, %s", err)
		}

		//log.Printf("%#v",v)

		if vx, ok := v["listen"].(string); !ok {
			log.Fatal("no listen address configed.")
		} else {
			LISTEN = vx
		}

		if vx, ok := v["server"].(string); !ok {
			log.Fatal("no server address configed.")
		} else {
			SERVER = vx
		}

		if _, ok := v["users"].([]interface{}); !ok {
			log.Fatal("no users configed.")
		}

		for _, vx := range v["users"].([]interface{}) {
			if _v, ok := vx.(string); ok {
				USERS = append(USERS, _v)
			}
		}

		//log.Printf("%#v",USERS)

		if len(USERS) < 1 {
			log.Fatal("no users configed.")
		}

		cf.Close()
	}

	ln, err := net.Listen("tcp", LISTEN)
	if err != nil {
		// handle error
		log.Fatal("tcp listen failed.")
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			continue
		}
		go handleConnection(conn)
	}
}
